rule sig_20161206_d54614b758e8201b82084d490cf47f81 {
  meta:
    description = "datamaliciousorder - file 20161206_d54614b758e8201b82084d490cf47f81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2838350ccbba0a41da33e0a5e4d92262083aff3f8917f8caf38781c9ee213538"

  strings:
    $s1 = "function _Yo3(s) {var _In9 = new Date();_In9.setUTCFullYear(\"2003\");if (_In9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Yo3(s) {var _In9 = new Date();_In9.setUTCFullYear(\"2003\");if (_In9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _FZi1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}