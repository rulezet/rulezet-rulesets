rule sig_20161205_2238297ee0f53e06183ca10165bb0f0b {
  meta:
    description = "datamaliciousorder - file 20161205_2238297ee0f53e06183ca10165bb0f0b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4aa7589cd7fac04c8e626a38dc2dd30ae50c65065120c71b622ef3551730b879"

  strings:
    $s1 = "function _YUk9(s) {var _Wf8 = new Date();_Wf8.setUTCFullYear(\"2003\");if (_Wf8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _YUk9(s) {var _Wf8 = new Date();_Wf8.setUTCFullYear(\"2003\");if (_Wf8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _QAb9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}