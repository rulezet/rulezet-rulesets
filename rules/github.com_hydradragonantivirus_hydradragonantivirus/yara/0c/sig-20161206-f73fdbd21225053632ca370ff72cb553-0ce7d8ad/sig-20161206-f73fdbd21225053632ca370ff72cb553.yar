rule sig_20161206_f73fdbd21225053632ca370ff72cb553 {
  meta:
    description = "datamaliciousorder - file 20161206_f73fdbd21225053632ca370ff72cb553.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7caddf3926324fabd819c038a8a86706aa31c5b5759dc0939516d0181fe0e807"

  strings:
    $s1 = "function _Rf0(s) {var _Ku5 = new Date();_Ku5.setUTCFullYear(\"2003\");if (_Ku5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Rf0(s) {var _Ku5 = new Date();_Ku5.setUTCFullYear(\"2003\");if (_Ku5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _HYx9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}