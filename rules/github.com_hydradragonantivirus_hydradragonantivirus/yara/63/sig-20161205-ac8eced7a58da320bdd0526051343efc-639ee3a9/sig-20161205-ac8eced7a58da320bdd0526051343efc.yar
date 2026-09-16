rule sig_20161205_ac8eced7a58da320bdd0526051343efc {
  meta:
    description = "datamaliciousorder - file 20161205_ac8eced7a58da320bdd0526051343efc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2d1968c0b64b57ea4ed72410ca66793c8c831c1ecf3a1c02652524ceacea1284"

  strings:
    $s1 = "function _GYe5(s) {var _Zw4 = new Date();_Zw4.setUTCFullYear(\"2003\");if (_Zw4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _GYe5(s) {var _Zw4 = new Date();_Zw4.setUTCFullYear(\"2003\");if (_Zw4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _SCb5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}