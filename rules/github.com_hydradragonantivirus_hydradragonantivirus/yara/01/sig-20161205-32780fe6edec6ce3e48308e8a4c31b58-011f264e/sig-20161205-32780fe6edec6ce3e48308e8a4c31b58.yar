rule sig_20161205_32780fe6edec6ce3e48308e8a4c31b58 {
  meta:
    description = "datamaliciousorder - file 20161205_32780fe6edec6ce3e48308e8a4c31b58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13f24f5d72f158b2251158448c275de740f0f5574441c6da87d066aecb079e4b"

  strings:
    $s1 = "function _SFm5(s) {var _Lc4 = new Date();_Lc4.setUTCFullYear(\"2003\");if (_Lc4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _SFm5(s) {var _Lc4 = new Date();_Lc4.setUTCFullYear(\"2003\");if (_Lc4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Du8(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}