rule sig_20161206_085d36bc716b72382bfb02afee35d178 {
  meta:
    description = "datamaliciousorder - file 20161206_085d36bc716b72382bfb02afee35d178.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72e0c21f0a00894f974e8061d515fc5705dc12b4d6c33e7168184180746519b0"

  strings:
    $s1 = "function _JUt1(s) {var _Ni6 = new Date();_Ni6.setUTCFullYear(\"2003\");if (_Ni6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _JUt1(s) {var _Ni6 = new Date();_Ni6.setUTCFullYear(\"2003\");if (_Ni6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _MKx6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}