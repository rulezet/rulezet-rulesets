rule sig_20161205_ba3eaadf4df6a3edea5c80400516b2a7 {
  meta:
    description = "datamaliciousorder - file 20161205_ba3eaadf4df6a3edea5c80400516b2a7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a61eef373228b2668de8df9b6b48cf9248febbf576a649583c5b4bb449e4f49e"

  strings:
    $s1 = "function _PFs8(s) {var _Ot3 = new Date();_Ot3.setUTCFullYear(\"2003\");if (_Ot3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _PFs8(s) {var _Ot3 = new Date();_Ot3.setUTCFullYear(\"2003\");if (_Ot3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _En9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}