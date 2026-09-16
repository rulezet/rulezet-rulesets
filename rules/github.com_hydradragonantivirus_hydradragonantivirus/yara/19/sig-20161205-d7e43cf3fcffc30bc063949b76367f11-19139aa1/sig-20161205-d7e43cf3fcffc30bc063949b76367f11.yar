rule sig_20161205_d7e43cf3fcffc30bc063949b76367f11 {
  meta:
    description = "datamaliciousorder - file 20161205_d7e43cf3fcffc30bc063949b76367f11.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "488a820381060cbcd9680d1c7b139e78e170735ae0a40c068ece4c832e2c2506"

  strings:
    $s1 = "function _Jp5(s) {var _Vo1 = new Date();_Vo1.setUTCFullYear(\"2003\");if (_Vo1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Jp5(s) {var _Vo1 = new Date();_Vo1.setUTCFullYear(\"2003\");if (_Vo1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Li5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}