rule sig_20161205_27109a37019b14b3b4ba2e394d4dcb93 {
  meta:
    description = "datamaliciousorder - file 20161205_27109a37019b14b3b4ba2e394d4dcb93.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5c05f4fac1d86c7eefc8d34e51deecc0243dabcde883f96f82bfd6349428d127"

  strings:
    $s1 = "function _Aa9(s) {var _DFw1 = new Date();_DFw1.setUTCFullYear(\"2003\");if (_DFw1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Aa9(s) {var _DFw1 = new Date();_DFw1.setUTCFullYear(\"2003\");if (_DFw1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Yx8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}