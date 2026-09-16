rule sig_20161206_a564e9c297016852cb97e29ea3e5fca0 {
  meta:
    description = "datamaliciousorder - file 20161206_a564e9c297016852cb97e29ea3e5fca0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a603a64f5f86e6677e3ba79643805f531d256a5ed5c366eec351e9510c011c8"

  strings:
    $s1 = "function _GOr3(s) {var _GZo2 = new Date();_GZo2.setUTCFullYear(\"2003\");if (_GZo2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _GOr3(s) {var _GZo2 = new Date();_GZo2.setUTCFullYear(\"2003\");if (_GZo2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _EXl8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}