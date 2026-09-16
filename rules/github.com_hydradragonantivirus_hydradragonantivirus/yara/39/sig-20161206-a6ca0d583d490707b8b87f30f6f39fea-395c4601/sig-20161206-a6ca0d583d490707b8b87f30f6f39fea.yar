rule sig_20161206_a6ca0d583d490707b8b87f30f6f39fea {
  meta:
    description = "datamaliciousorder - file 20161206_a6ca0d583d490707b8b87f30f6f39fea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bdb3ae72962ed475f0a47907428bf16cac5c78d622b77de8168eab13dab6cbb2"

  strings:
    $s1 = "function _Wi0(s) {var _Tu8 = new Date();_Tu8.setUTCFullYear(\"2003\");if (_Tu8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Wi0(s) {var _Tu8 = new Date();_Tu8.setUTCFullYear(\"2003\");if (_Tu8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _MXg1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}