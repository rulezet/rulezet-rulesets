rule sig_20161206_1495332bbc8fd59e4dc509f8bae952b2 {
  meta:
    description = "datamaliciousorder - file 20161206_1495332bbc8fd59e4dc509f8bae952b2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7867b1145e6ae3d5fe1a5f3a08bc5f122145c0665f3dadf6593fc9e32dfeb36d"

  strings:
    $s1 = "function _Om6(s) {var _Ot0 = new Date();_Ot0.setUTCFullYear(\"2003\");if (_Ot0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Om6(s) {var _Ot0 = new Date();_Ot0.setUTCFullYear(\"2003\");if (_Ot0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Re3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}