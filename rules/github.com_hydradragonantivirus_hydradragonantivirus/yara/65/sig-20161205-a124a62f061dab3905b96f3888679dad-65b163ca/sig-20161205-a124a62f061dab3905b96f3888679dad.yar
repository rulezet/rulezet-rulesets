rule sig_20161205_a124a62f061dab3905b96f3888679dad {
  meta:
    description = "datamaliciousorder - file 20161205_a124a62f061dab3905b96f3888679dad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "322f4b97f948c55b1eaef2c5175fdfe709088f638c2167b745061aed7bbb0f79"

  strings:
    $s1 = "function _OHi4(s) {var _Ra5 = new Date();_Ra5.setUTCFullYear(\"2003\");if (_Ra5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _OHi4(s) {var _Ra5 = new Date();_Ra5.setUTCFullYear(\"2003\");if (_Ra5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _LRn3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}