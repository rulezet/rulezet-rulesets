rule sig_20161205_c2c651584772a982dd3843d112632b17 {
  meta:
    description = "datamaliciousorder - file 20161205_c2c651584772a982dd3843d112632b17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0dcb87f95ef9895b8a25ebcf4bf7d3f5364532c7b0da57682abd6b0df52897ff"

  strings:
    $s1 = "function _HLo8(s) {var _VJj9 = new Date();_VJj9.setUTCFullYear(\"2003\");if (_VJj9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _HLo8(s) {var _VJj9 = new Date();_VJj9.setUTCFullYear(\"2003\");if (_VJj9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Kc0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}