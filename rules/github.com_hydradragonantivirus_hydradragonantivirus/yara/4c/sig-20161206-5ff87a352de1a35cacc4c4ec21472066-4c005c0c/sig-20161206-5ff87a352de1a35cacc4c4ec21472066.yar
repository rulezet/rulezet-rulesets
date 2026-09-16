rule sig_20161206_5ff87a352de1a35cacc4c4ec21472066 {
  meta:
    description = "datamaliciousorder - file 20161206_5ff87a352de1a35cacc4c4ec21472066.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27618d5477940be5b4dff84f57b5e307aae802ffac0e3889d42a8215c680a8ba"

  strings:
    $s1 = "function _Bo8(s) {var _Cw9 = new Date();_Cw9.setUTCFullYear(\"2003\");if (_Cw9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Bo8(s) {var _Cw9 = new Date();_Cw9.setUTCFullYear(\"2003\");if (_Cw9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Ji8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}