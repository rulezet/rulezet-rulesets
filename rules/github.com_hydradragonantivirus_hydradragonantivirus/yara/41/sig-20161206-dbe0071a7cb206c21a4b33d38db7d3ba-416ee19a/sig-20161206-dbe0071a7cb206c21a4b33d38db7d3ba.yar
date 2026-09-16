rule sig_20161206_dbe0071a7cb206c21a4b33d38db7d3ba {
  meta:
    description = "datamaliciousorder - file 20161206_dbe0071a7cb206c21a4b33d38db7d3ba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "43c2928f1f2ce88bfc828b9ee68c331a731c784925b39be17ab453664f7073aa"

  strings:
    $s1 = "function _YSo4(s) {var _Yd8 = new Date();_Yd8.setUTCFullYear(\"2003\");if (_Yd8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _YSo4(s) {var _Yd8 = new Date();_Yd8.setUTCFullYear(\"2003\");if (_Yd8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _OXm8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}