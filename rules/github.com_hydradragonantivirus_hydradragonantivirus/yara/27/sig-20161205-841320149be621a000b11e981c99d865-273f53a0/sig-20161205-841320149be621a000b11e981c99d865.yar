rule sig_20161205_841320149be621a000b11e981c99d865 {
  meta:
    description = "datamaliciousorder - file 20161205_841320149be621a000b11e981c99d865.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fad9487037b5a389de9bac4646b5a56b944e39813bfe25bbb3926cdd6c43641"

  strings:
    $s1 = "function _Lu1(s) {var _Cf1 = new Date();_Cf1.setUTCFullYear(\"2003\");if (_Cf1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Lu1(s) {var _Cf1 = new Date();_Cf1.setUTCFullYear(\"2003\");if (_Cf1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Ap3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}