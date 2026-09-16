rule sig_20161206_2b735549f0f19c6babb0fd3a71ffc46e {
  meta:
    description = "datamaliciousorder - file 20161206_2b735549f0f19c6babb0fd3a71ffc46e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81fc44802621a3dcdb6275e5f5969eb21299940b746719bdc062910be4b5abc7"

  strings:
    $s1 = "function _Mp6(s) {var _PMv5 = new Date();_PMv5.setUTCFullYear(\"2003\");if (_PMv5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Mp6(s) {var _PMv5 = new Date();_PMv5.setUTCFullYear(\"2003\");if (_PMv5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ko2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}