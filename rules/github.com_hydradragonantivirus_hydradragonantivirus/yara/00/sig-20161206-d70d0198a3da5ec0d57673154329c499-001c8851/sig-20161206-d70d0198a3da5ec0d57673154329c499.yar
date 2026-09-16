rule sig_20161206_d70d0198a3da5ec0d57673154329c499 {
  meta:
    description = "datamaliciousorder - file 20161206_d70d0198a3da5ec0d57673154329c499.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73ea58ff25f50ae32fbef75a056315c22bbaac8ff5a0f0e92d56aa9c126ec8c7"

  strings:
    $s1 = "function _SBq3(s) {var _CQa3 = new Date();_CQa3.setUTCFullYear(\"2003\");if (_CQa3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _SBq3(s) {var _CQa3 = new Date();_CQa3.setUTCFullYear(\"2003\");if (_CQa3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _El6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}