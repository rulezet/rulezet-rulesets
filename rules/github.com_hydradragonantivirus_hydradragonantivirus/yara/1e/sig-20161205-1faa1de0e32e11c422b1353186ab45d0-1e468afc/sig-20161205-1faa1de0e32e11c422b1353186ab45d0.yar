rule sig_20161205_1faa1de0e32e11c422b1353186ab45d0 {
  meta:
    description = "datamaliciousorder - file 20161205_1faa1de0e32e11c422b1353186ab45d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27fa3072066ce05d7b104c97a0aa6ea59088ed0aa3d791b4c729fa20029fb37e"

  strings:
    $s1 = "function _Rv3(s) {var _Gw3 = new Date();_Gw3.setUTCFullYear(\"2003\");if (_Gw3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Rv3(s) {var _Gw3 = new Date();_Gw3.setUTCFullYear(\"2003\");if (_Gw3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Yb2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}