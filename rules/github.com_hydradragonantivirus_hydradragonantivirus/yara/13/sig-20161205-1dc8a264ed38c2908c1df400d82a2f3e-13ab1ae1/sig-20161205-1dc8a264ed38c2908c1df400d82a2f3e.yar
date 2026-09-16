rule sig_20161205_1dc8a264ed38c2908c1df400d82a2f3e {
  meta:
    description = "datamaliciousorder - file 20161205_1dc8a264ed38c2908c1df400d82a2f3e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e33e86e8b825a47518d8ba26e4abb2a40e6201a4ab9f86aff01ee77f2298fb2"

  strings:
    $s1 = "function _PFl2(s) {var _Ia7 = new Date();_Ia7.setUTCFullYear(\"2003\");if (_Ia7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _PFl2(s) {var _Ia7 = new Date();_Ia7.setUTCFullYear(\"2003\");if (_Ia7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Cf9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}