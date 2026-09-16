rule sig_20161205_7b0031a7121f3c379e8cdf05baf85828 {
  meta:
    description = "datamaliciousorder - file 20161205_7b0031a7121f3c379e8cdf05baf85828.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e03d03385a3170b8fe2268441f3fed9c95dc471c39d0b2cf04453daf259d6133"

  strings:
    $s1 = "function _Ri3(s) {var _LHl4 = new Date();_LHl4.setUTCFullYear(\"2003\");if (_LHl4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ri3(s) {var _LHl4 = new Date();_LHl4.setUTCFullYear(\"2003\");if (_LHl4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Xp1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}