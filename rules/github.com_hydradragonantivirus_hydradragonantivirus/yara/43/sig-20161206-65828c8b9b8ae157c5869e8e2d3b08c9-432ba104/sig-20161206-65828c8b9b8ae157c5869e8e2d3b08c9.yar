rule sig_20161206_65828c8b9b8ae157c5869e8e2d3b08c9 {
  meta:
    description = "datamaliciousorder - file 20161206_65828c8b9b8ae157c5869e8e2d3b08c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "08b79423e8db304f82c0008a37523b0938f7bdf25f2cd0356136f58b6a8705db"

  strings:
    $s1 = "function _Ju3(s) {var _Vl1 = new Date();_Vl1.setUTCFullYear(\"2003\");if (_Vl1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ju3(s) {var _Vl1 = new Date();_Vl1.setUTCFullYear(\"2003\");if (_Vl1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _HRr0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}