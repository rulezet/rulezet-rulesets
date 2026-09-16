rule sig_20161205_1f1eae4bb882617b852f5a86188bc16d {
  meta:
    description = "datamaliciousorder - file 20161205_1f1eae4bb882617b852f5a86188bc16d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71e074126d402c0196a7e18bec6f92c15f6bb2d1c27b22ae197ff00dc6106a16"

  strings:
    $s1 = "function _Vn8(s) {var _Ym8 = new Date();_Ym8.setUTCFullYear(\"2003\");if (_Ym8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Vn8(s) {var _Ym8 = new Date();_Ym8.setUTCFullYear(\"2003\");if (_Ym8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Ux3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}