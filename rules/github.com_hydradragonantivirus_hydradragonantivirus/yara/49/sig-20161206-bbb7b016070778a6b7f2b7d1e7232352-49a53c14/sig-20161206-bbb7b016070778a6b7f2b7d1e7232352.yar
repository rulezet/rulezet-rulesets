rule sig_20161206_bbb7b016070778a6b7f2b7d1e7232352 {
  meta:
    description = "datamaliciousorder - file 20161206_bbb7b016070778a6b7f2b7d1e7232352.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81c13d6c0fa84af51c6ab4ac8de300c7c9527667f849c6090440a3951171bdd8"

  strings:
    $s1 = "function _Cx8(s) {var _Hl6 = new Date();_Hl6.setUTCFullYear(\"2003\");if (_Hl6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Cx8(s) {var _Hl6 = new Date();_Hl6.setUTCFullYear(\"2003\");if (_Hl6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Yr3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}