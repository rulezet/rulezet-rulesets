rule sig_20161205_7e18c5c4d25254c48459fd4c255da9a3 {
  meta:
    description = "datamaliciousorder - file 20161205_7e18c5c4d25254c48459fd4c255da9a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3f1c86742a5034a47cea4612644b918fa009be9ae424f131557de7de4ddcf499"

  strings:
    $s1 = "function _UBv9(s) {var _Ns1 = new Date();_Ns1.setUTCFullYear(\"2003\");if (_Ns1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _UBv9(s) {var _Ns1 = new Date();_Ns1.setUTCFullYear(\"2003\");if (_Ns1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Xp1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}