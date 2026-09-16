rule sig_20161205_b61f1c50e7205ae0926c0c7ff08a69c0 {
  meta:
    description = "datamaliciousorder - file 20161205_b61f1c50e7205ae0926c0c7ff08a69c0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dbc17f3823132d37c1897de0f8db3bdd5371e4fd6430206436a8ea1dd21b962"

  strings:
    $s1 = "function _KJa4(s) {var _Zo5 = new Date();_Zo5.setUTCFullYear(\"2003\");if (_Zo5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _KJa4(s) {var _Zo5 = new Date();_Zo5.setUTCFullYear(\"2003\");if (_Zo5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _FCd1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}