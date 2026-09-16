rule sig_20161206_bed3017bef0bd3622e019dacf9c90c5b {
  meta:
    description = "datamaliciousorder - file 20161206_bed3017bef0bd3622e019dacf9c90c5b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2003ceb678a0dbb00812389c1dfcfd396c6c5b83ebcf5598ee21112f1dbfd984"

  strings:
    $s1 = "function _Aj8(s) {var _Ff1 = new Date();_Ff1.setUTCFullYear(\"2003\");if (_Ff1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Aj8(s) {var _Ff1 = new Date();_Ff1.setUTCFullYear(\"2003\");if (_Ff1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _XMy1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}