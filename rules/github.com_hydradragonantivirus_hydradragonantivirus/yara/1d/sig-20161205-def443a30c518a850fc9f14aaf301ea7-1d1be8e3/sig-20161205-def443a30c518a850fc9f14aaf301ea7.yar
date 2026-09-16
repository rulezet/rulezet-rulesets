rule sig_20161205_def443a30c518a850fc9f14aaf301ea7 {
  meta:
    description = "datamaliciousorder - file 20161205_def443a30c518a850fc9f14aaf301ea7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2aeffb7158ad2908a3b6c8473ea9dfea0c9d0c815908e874ba3d6bbf6211ee25"

  strings:
    $s1 = "function _Qx9(s) {var _Sh6 = new Date();_Sh6.setUTCFullYear(\"2003\");if (_Sh6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Qx9(s) {var _Sh6 = new Date();_Sh6.setUTCFullYear(\"2003\");if (_Sh6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _XAw1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}