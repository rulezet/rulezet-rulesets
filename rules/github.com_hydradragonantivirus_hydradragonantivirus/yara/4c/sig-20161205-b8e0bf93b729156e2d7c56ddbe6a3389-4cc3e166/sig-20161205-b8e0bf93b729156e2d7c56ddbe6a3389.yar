rule sig_20161205_b8e0bf93b729156e2d7c56ddbe6a3389 {
  meta:
    description = "datamaliciousorder - file 20161205_b8e0bf93b729156e2d7c56ddbe6a3389.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bfc30de5743f62bfabaac23f86f8d6c27b733eb6acfcae3719abe110aaf2c09"

  strings:
    $s1 = "function _TOd2(s) {var _FTc8 = new Date();_FTc8.setUTCFullYear(\"2003\");if (_FTc8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _TOd2(s) {var _FTc8 = new Date();_FTc8.setUTCFullYear(\"2003\");if (_FTc8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _PVr5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}