rule sig_20161206_e076e723d18358daf46ef5bad67ddef7 {
  meta:
    description = "datamaliciousorder - file 20161206_e076e723d18358daf46ef5bad67ddef7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a21b7833b1a9f999bb8a1f94137a8f375f11f72475bb47d92f7a6f8df908b229"

  strings:
    $s1 = "function _Nw2(s) {var _YDl6 = new Date();_YDl6.setUTCFullYear(\"2003\");if (_YDl6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Nw2(s) {var _YDl6 = new Date();_YDl6.setUTCFullYear(\"2003\");if (_YDl6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _HLs5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}