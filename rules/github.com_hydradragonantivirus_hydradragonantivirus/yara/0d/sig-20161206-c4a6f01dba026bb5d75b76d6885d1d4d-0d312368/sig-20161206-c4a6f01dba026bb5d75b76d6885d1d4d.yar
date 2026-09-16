rule sig_20161206_c4a6f01dba026bb5d75b76d6885d1d4d {
  meta:
    description = "datamaliciousorder - file 20161206_c4a6f01dba026bb5d75b76d6885d1d4d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c8809cfa2eee8f722e7f0be4c486cd6c47a0553fa18250319162ddc7b4e3530"

  strings:
    $s1 = "function _At5(s) {var _JIn6 = new Date();_JIn6.setUTCFullYear(\"2003\");if (_JIn6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _At5(s) {var _JIn6 = new Date();_JIn6.setUTCFullYear(\"2003\");if (_JIn6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _YFs3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}