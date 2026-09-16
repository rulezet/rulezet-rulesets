rule sig_20161205_abca6ecb28fe2f51c65a47041e3e1812 {
  meta:
    description = "datamaliciousorder - file 20161205_abca6ecb28fe2f51c65a47041e3e1812.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60f1405c12542c527ce94f65ce9e7e1ac22584436ac701c1197e1b8cfc99f81d"

  strings:
    $s1 = "function _WIu5(s) {var _VKi5 = new Date();_VKi5.setUTCFullYear(\"2003\");if (_VKi5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _WIu5(s) {var _VKi5 = new Date();_VKi5.setUTCFullYear(\"2003\");if (_VKi5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Xx9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}