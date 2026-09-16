rule sig_20161206_3bf4deb5e0eb4495b6a09d8f597756e9 {
  meta:
    description = "datamaliciousorder - file 20161206_3bf4deb5e0eb4495b6a09d8f597756e9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dec79da2bfc9342d0cad4e9550c46b917d22eec2d3a822629bd448faf0b63643"

  strings:
    $s1 = "function _ZWx8(s) {var _NWn0 = new Date();_NWn0.setUTCFullYear(\"2003\");if (_NWn0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _ZWx8(s) {var _NWn0 = new Date();_NWn0.setUTCFullYear(\"2003\");if (_NWn0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _LHc9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}