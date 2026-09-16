rule sig_20161205_4d27646b64bc2a7d2808c8a268af9972 {
  meta:
    description = "datamaliciousorder - file 20161205_4d27646b64bc2a7d2808c8a268af9972.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "139cd0d0850b8d0d27425d6bcd0713248309e4395ece5bb5f9cd42375179a9a7"

  strings:
    $s1 = "function _LRx3(s) {var _NDo5 = new Date();_NDo5.setUTCFullYear(\"2003\");if (_NDo5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _LRx3(s) {var _NDo5 = new Date();_NDo5.setUTCFullYear(\"2003\");if (_NDo5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Id6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}