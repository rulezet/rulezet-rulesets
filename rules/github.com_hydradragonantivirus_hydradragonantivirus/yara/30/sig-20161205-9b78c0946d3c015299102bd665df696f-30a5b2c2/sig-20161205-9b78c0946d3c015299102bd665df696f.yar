rule sig_20161205_9b78c0946d3c015299102bd665df696f {
  meta:
    description = "datamaliciousorder - file 20161205_9b78c0946d3c015299102bd665df696f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5750b6be279a78aafa821b3ca8512b1c4dad58e34530e3a97d0e2fb2bd12f0dd"

  strings:
    $s1 = "function _Gz1(s) {var _LTl8 = new Date();_LTl8.setUTCFullYear(\"2003\");if (_LTl8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Gz1(s) {var _LTl8 = new Date();_LTl8.setUTCFullYear(\"2003\");if (_LTl8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _GPq4(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}