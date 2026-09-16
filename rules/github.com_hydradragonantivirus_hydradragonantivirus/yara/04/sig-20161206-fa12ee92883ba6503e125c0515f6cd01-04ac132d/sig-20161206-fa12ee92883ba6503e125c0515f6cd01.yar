rule sig_20161206_fa12ee92883ba6503e125c0515f6cd01 {
  meta:
    description = "datamaliciousorder - file 20161206_fa12ee92883ba6503e125c0515f6cd01.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e739b54f75f55e2dda59aacc5f5f5b802abd439b73732cd4568ed73de8364429"

  strings:
    $s1 = "function _XAb1(s) {var _RUy7 = new Date();_RUy7.setUTCFullYear(\"2003\");if (_RUy7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _XAb1(s) {var _RUy7 = new Date();_RUy7.setUTCFullYear(\"2003\");if (_RUy7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _DYw3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}