rule sig_20161206_9eb60d14e3cd9a2b4f29d697ff703c3d {
  meta:
    description = "datamaliciousorder - file 20161206_9eb60d14e3cd9a2b4f29d697ff703c3d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1cfd03676744fcf69e8003435b0a4a4a51fbe50591117f507a46303b59628a43"

  strings:
    $s1 = "function _Tv8(s) {var _Gh8 = new Date();_Gh8.setUTCFullYear(\"2003\");if (_Gh8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Tv8(s) {var _Gh8 = new Date();_Gh8.setUTCFullYear(\"2003\");if (_Gh8.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _AAk7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}