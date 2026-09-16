rule sig_20161206_b5ca97a048395e4e0f02439f296225fe {
  meta:
    description = "datamaliciousorder - file 20161206_b5ca97a048395e4e0f02439f296225fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "232708fef7e89f233baa06b996c1d33657e7424ccd69e2bba225c864ca7f1739"

  strings:
    $s1 = "function _PKx7(s) {var _GPl7 = new Date();_GPl7.setUTCFullYear(\"2003\");if (_GPl7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _PKx7(s) {var _GPl7 = new Date();_GPl7.setUTCFullYear(\"2003\");if (_GPl7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _SIp8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}