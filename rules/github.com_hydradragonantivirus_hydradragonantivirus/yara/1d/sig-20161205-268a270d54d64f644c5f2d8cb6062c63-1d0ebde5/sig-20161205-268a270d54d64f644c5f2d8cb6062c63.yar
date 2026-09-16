rule sig_20161205_268a270d54d64f644c5f2d8cb6062c63 {
  meta:
    description = "datamaliciousorder - file 20161205_268a270d54d64f644c5f2d8cb6062c63.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "525305749362fbe8760e18afba00b5b9d4684ba99fc7c8c404795a94a0bd319c"

  strings:
    $s1 = "function _IWj9(s) {var _Hd7 = new Date();_Hd7.setUTCFullYear(\"2003\");if (_Hd7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _IWj9(s) {var _Hd7 = new Date();_Hd7.setUTCFullYear(\"2003\");if (_Hd7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Tq1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}