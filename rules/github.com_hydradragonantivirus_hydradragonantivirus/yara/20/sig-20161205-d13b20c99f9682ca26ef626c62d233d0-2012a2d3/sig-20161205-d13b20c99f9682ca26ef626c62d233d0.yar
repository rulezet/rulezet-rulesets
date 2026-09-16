rule sig_20161205_d13b20c99f9682ca26ef626c62d233d0 {
  meta:
    description = "datamaliciousorder - file 20161205_d13b20c99f9682ca26ef626c62d233d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ee926466eba8d4b97feff8a565cf7176c7a354dd036a2a2ddefb44d3cdd7fe07"

  strings:
    $s1 = "function _Ww5(s) {var _ODp3 = new Date();_ODp3.setUTCFullYear(\"2003\");if (_ODp3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ww5(s) {var _ODp3 = new Date();_ODp3.setUTCFullYear(\"2003\");if (_ODp3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _GIl8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}