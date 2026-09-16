rule sig_20161205_e8e851cc4ed4a6766d253e0370767055 {
  meta:
    description = "datamaliciousorder - file 20161205_e8e851cc4ed4a6766d253e0370767055.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14a9db64d92305f9af98d727a917432d84773a008110043eb00d15a5ec8c3f02"

  strings:
    $s1 = "function _QYg6(s) {var _Ia2 = new Date();_Ia2.setUTCFullYear(\"2003\");if (_Ia2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _QYg6(s) {var _Ia2 = new Date();_Ia2.setUTCFullYear(\"2003\");if (_Ia2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Md7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}