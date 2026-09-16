rule sig_20161205_20f388b18789b338313eda9041acb842 {
  meta:
    description = "datamaliciousorder - file 20161205_20f388b18789b338313eda9041acb842.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8f32697848a81fefc9ee5d7a9574fe3823c8de86c0d25689e1da557f33ebd238"

  strings:
    $s1 = "function _KAy1(s) {var _UPi0 = new Date();_UPi0.setUTCFullYear(\"2003\");if (_UPi0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _KAy1(s) {var _UPi0 = new Date();_UPi0.setUTCFullYear(\"2003\");if (_UPi0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _BLl9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}