rule sig_20161205_d662600f00601c9563431c28c52a2179 {
  meta:
    description = "datamaliciousorder - file 20161205_d662600f00601c9563431c28c52a2179.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ff6c1bed610dc76131fe0990816d329029563a718984c307e2050c0270271a65"

  strings:
    $s1 = "function _Hd9(s) {var _Zl3 = new Date();_Zl3.setUTCFullYear(\"2003\");if (_Zl3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Hd9(s) {var _Zl3 = new Date();_Zl3.setUTCFullYear(\"2003\");if (_Zl3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _OOc1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}