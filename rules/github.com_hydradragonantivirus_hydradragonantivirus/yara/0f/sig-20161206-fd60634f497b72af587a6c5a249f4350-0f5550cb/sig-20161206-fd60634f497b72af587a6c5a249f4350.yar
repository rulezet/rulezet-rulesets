rule sig_20161206_fd60634f497b72af587a6c5a249f4350 {
  meta:
    description = "datamaliciousorder - file 20161206_fd60634f497b72af587a6c5a249f4350.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b63c2878d7e6c27f09e0ec42c4654bea134109f94936e28b7a5f40abe1078215"

  strings:
    $s1 = "function _Dp7(s) {var _Ao9 = new Date();_Ao9.setUTCFullYear(\"2003\");if (_Ao9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Dp7(s) {var _Ao9 = new Date();_Ao9.setUTCFullYear(\"2003\");if (_Ao9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Jr6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}