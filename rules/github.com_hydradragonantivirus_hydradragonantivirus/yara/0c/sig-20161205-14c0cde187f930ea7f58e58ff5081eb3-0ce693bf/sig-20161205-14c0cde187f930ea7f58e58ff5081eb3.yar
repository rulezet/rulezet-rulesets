rule sig_20161205_14c0cde187f930ea7f58e58ff5081eb3 {
  meta:
    description = "datamaliciousorder - file 20161205_14c0cde187f930ea7f58e58ff5081eb3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e68d22cc4ea56f68a5a362cfcc751e231d41094ad606c3b9c601562f97151c8c"

  strings:
    $s1 = "function _Pf7(s) {var _CIq2 = new Date();_CIq2.setUTCFullYear(\"2003\");if (_CIq2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Pf7(s) {var _CIq2 = new Date();_CIq2.setUTCFullYear(\"2003\");if (_CIq2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Oo7(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}