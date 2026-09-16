rule sig_20161206_f63fc4e9489e5416e1ff8d87950e7b10 {
  meta:
    description = "datamaliciousorder - file 20161206_f63fc4e9489e5416e1ff8d87950e7b10.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "20aff186fadd37ac5a5845be760e4f834492f5883d2315fa849311133b64c569"

  strings:
    $s1 = "function _Dt8(s) {var _Rl5 = new Date();_Rl5.setUTCFullYear(\"2003\");if (_Rl5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Dt8(s) {var _Rl5 = new Date();_Rl5.setUTCFullYear(\"2003\");if (_Rl5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _HBb4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}