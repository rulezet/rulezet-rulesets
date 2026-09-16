rule sig_20161205_7c68dc4955fa7e069889a79ce5150360 {
  meta:
    description = "datamaliciousorder - file 20161205_7c68dc4955fa7e069889a79ce5150360.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "557e6f7b3dccac1ed98a5e3309e61392420e4a22cb73c18e848e9c5fd0952e6e"

  strings:
    $s1 = "function _DAx4(s) {var _Hy3 = new Date();_Hy3.setUTCFullYear(\"2003\");if (_Hy3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _DAx4(s) {var _Hy3 = new Date();_Hy3.setUTCFullYear(\"2003\");if (_Hy3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Er1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}