rule sig_20161206_10c4cad5315ed42885b4fddf0dad4724 {
  meta:
    description = "datamaliciousorder - file 20161206_10c4cad5315ed42885b4fddf0dad4724.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "77e3e3ad77bafec21ec658b28fdf9f24532f372cb45a5bc2a7d1482d8df1cc8d"

  strings:
    $s1 = "function _Nf6(s) {var _RKs3 = new Date();_RKs3.setUTCFullYear(\"2003\");if (_RKs3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Nf6(s) {var _RKs3 = new Date();_RKs3.setUTCFullYear(\"2003\");if (_RKs3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _HYx0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}