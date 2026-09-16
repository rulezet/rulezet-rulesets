rule sig_20161205_a12af4df06c1ff70087ac73441e1bb13 {
  meta:
    description = "datamaliciousorder - file 20161205_a12af4df06c1ff70087ac73441e1bb13.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0302e2845a24d0910285fda1bc3f67efd0b7af26b486dc0aee6e4c5f60d643d9"

  strings:
    $s1 = "function _Mn5(s) {var _Wy4 = new Date();_Wy4.setUTCFullYear(\"2003\");if (_Wy4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Mn5(s) {var _Wy4 = new Date();_Wy4.setUTCFullYear(\"2003\");if (_Wy4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _JKu1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}