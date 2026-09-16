rule sig_20161206_5ec092b5d947d323cf452cbf1dffcec5 {
  meta:
    description = "datamaliciousorder - file 20161206_5ec092b5d947d323cf452cbf1dffcec5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8febec4a576525fb5cc8cfffb3a71b0a21fbb616fe87116952d06b785973e06"

  strings:
    $s1 = "function _Th3(s) {var _PRj0 = new Date();_PRj0.setUTCFullYear(\"2003\");if (_PRj0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Th3(s) {var _PRj0 = new Date();_PRj0.setUTCFullYear(\"2003\");if (_PRj0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Yo1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}