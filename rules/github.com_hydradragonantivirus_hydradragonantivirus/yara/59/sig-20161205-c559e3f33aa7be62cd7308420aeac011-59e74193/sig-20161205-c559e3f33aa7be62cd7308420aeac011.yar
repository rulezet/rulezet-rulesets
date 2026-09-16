rule sig_20161205_c559e3f33aa7be62cd7308420aeac011 {
  meta:
    description = "datamaliciousorder - file 20161205_c559e3f33aa7be62cd7308420aeac011.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ba7e6ec8f3c79a7b485c7d46156e29f2bc42f7122de36e4a90fa7bad0184e7da"

  strings:
    $s1 = "function _Yr4(s) {var _SSy5 = new Date();_SSy5.setUTCFullYear(\"2003\");if (_SSy5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Yr4(s) {var _SSy5 = new Date();_SSy5.setUTCFullYear(\"2003\");if (_SSy5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _UYh2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}