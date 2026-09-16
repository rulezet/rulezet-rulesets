rule sig_20161206_05636c3f3853e00cf6b06d43f8b7d009 {
  meta:
    description = "datamaliciousorder - file 20161206_05636c3f3853e00cf6b06d43f8b7d009.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "beb37e9a335aeae2e24cd42b677d895c1ffbbbdeff5ba56e4c7a6c46d67a8fe9"

  strings:
    $s1 = "function _ECa8(s) {var _SNk7 = new Date();_SNk7.setUTCFullYear(\"2003\");if (_SNk7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _ECa8(s) {var _SNk7 = new Date();_SNk7.setUTCFullYear(\"2003\");if (_SNk7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _ZBd4(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}