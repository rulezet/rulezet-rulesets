rule sig_20161205_de6b7764c32cae6754f06f99d8c0befa {
  meta:
    description = "datamaliciousorder - file 20161205_de6b7764c32cae6754f06f99d8c0befa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ddabd09dd97cff211d96d0c431a98877697b4227cc779350c6db1862e3def8f"

  strings:
    $s1 = "function _Dt6(s) {var _Mb9 = new Date();_Mb9.setUTCFullYear(\"2003\");if (_Mb9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Dt6(s) {var _Mb9 = new Date();_Mb9.setUTCFullYear(\"2003\");if (_Mb9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Uc5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}