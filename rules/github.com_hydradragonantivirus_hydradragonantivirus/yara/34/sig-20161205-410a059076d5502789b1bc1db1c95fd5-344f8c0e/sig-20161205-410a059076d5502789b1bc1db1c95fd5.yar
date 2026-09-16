rule sig_20161205_410a059076d5502789b1bc1db1c95fd5 {
  meta:
    description = "datamaliciousorder - file 20161205_410a059076d5502789b1bc1db1c95fd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "04c4167343d379de96da4ef0fe6559ead2ef74b0a13485f3af195c9e8dc9b3d6"

  strings:
    $s1 = "function _Sh9(s) {var _FAy0 = new Date();_FAy0.setUTCFullYear(\"2003\");if (_FAy0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Sh9(s) {var _FAy0 = new Date();_FAy0.setUTCFullYear(\"2003\");if (_FAy0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Uc2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}