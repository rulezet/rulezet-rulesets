rule sig_20161205_5c62feb05c0666d46af011c2d3c98d2f {
  meta:
    description = "datamaliciousorder - file 20161205_5c62feb05c0666d46af011c2d3c98d2f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "649f70d084749e79bacfa5bf9f6fd9f47ea3d7c4c9705a18ba2c71fdf23b3a6e"

  strings:
    $s1 = "function _Tz3(s) {var _ENz7 = new Date();_ENz7.setUTCFullYear(\"2003\");if (_ENz7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Tz3(s) {var _ENz7 = new Date();_ENz7.setUTCFullYear(\"2003\");if (_ENz7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _NIp2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}