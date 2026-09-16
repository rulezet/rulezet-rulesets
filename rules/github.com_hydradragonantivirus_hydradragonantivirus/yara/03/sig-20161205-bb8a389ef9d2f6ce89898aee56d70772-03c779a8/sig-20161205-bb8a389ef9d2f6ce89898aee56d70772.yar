rule sig_20161205_bb8a389ef9d2f6ce89898aee56d70772 {
  meta:
    description = "datamaliciousorder - file 20161205_bb8a389ef9d2f6ce89898aee56d70772.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f976eb715ee627b9ac949075dfd4cd9a5fa3ff717c6382ae149d21a476536390"

  strings:
    $s1 = "function _Ip7(s) {var _Hk1 = new Date();_Hk1.setUTCFullYear(\"2003\");if (_Hk1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ip7(s) {var _Hk1 = new Date();_Hk1.setUTCFullYear(\"2003\");if (_Hk1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Bp0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}