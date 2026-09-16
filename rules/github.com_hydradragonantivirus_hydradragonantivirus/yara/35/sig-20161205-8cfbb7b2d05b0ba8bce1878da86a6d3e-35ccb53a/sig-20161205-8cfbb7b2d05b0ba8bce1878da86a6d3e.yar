rule sig_20161205_8cfbb7b2d05b0ba8bce1878da86a6d3e {
  meta:
    description = "datamaliciousorder - file 20161205_8cfbb7b2d05b0ba8bce1878da86a6d3e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29945131caf44197d6d2a480051294a83a96f3208b4f4b9e55592fba8fc97e0c"

  strings:
    $s1 = "function _MVo5(s) {var _Hv3 = new Date();_Hv3.setUTCFullYear(\"2003\");if (_Hv3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _MVo5(s) {var _Hv3 = new Date();_Hv3.setUTCFullYear(\"2003\");if (_Hv3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Gl4(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}