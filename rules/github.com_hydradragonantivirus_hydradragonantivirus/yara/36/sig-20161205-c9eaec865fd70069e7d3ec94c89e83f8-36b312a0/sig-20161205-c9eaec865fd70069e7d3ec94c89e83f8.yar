rule sig_20161205_c9eaec865fd70069e7d3ec94c89e83f8 {
  meta:
    description = "datamaliciousorder - file 20161205_c9eaec865fd70069e7d3ec94c89e83f8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a3085dbb5f623f8cd44977fb1014c731fe92255b9b5d006733323521e812d4ee"

  strings:
    $s1 = "function _Sg5(s) {var _WNh5 = new Date();_WNh5.setUTCFullYear(\"2003\");if (_WNh5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Sg5(s) {var _WNh5 = new Date();_WNh5.setUTCFullYear(\"2003\");if (_WNh5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _JDc6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}