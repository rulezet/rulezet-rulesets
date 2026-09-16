rule sig_20161205_ff77279b3bae179e4ea0bc48d3fc236b {
  meta:
    description = "datamaliciousorder - file 20161205_ff77279b3bae179e4ea0bc48d3fc236b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e9b081d2d43fe0846bdf4fa1884b392e870f6d4b9240261d8308a5031b4e098"

  strings:
    $s1 = "function _FLu7(s) {var _ZTh1 = new Date();_ZTh1.setUTCFullYear(\"2003\");if (_ZTh1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _FLu7(s) {var _ZTh1 = new Date();_ZTh1.setUTCFullYear(\"2003\");if (_ZTh1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Hu9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}