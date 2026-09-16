rule sig_20161205_98de40677023d1fdfacabfd80caaf523 {
  meta:
    description = "datamaliciousorder - file 20161205_98de40677023d1fdfacabfd80caaf523.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77d0a5e32cfb6e451f85acc46ce543bfebf690672d67a5f300766edac1af110a"

  strings:
    $s1 = "function _Dd4(s) {var _Gw7 = new Date();_Gw7.setUTCFullYear(\"2003\");if (_Gw7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Dd4(s) {var _Gw7 = new Date();_Gw7.setUTCFullYear(\"2003\");if (_Gw7.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Qz6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}