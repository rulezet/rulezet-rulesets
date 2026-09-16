rule sig_20161205_08070b4204fa8045ad435abbeaa89569 {
  meta:
    description = "datamaliciousorder - file 20161205_08070b4204fa8045ad435abbeaa89569.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b01ede4e43b8554197ef861617ee8dd7307242e6d6062c4418a653b81c8d2038"

  strings:
    $s1 = "function _BJm3(s) {var _Ct6 = new Date();_Ct6.setUTCFullYear(\"2003\");if (_Ct6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _BJm3(s) {var _Ct6 = new Date();_Ct6.setUTCFullYear(\"2003\");if (_Ct6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Oa2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}