rule sig_20161205_d588b4c1dca376a47729c219c35dde2d {
  meta:
    description = "datamaliciousorder - file 20161205_d588b4c1dca376a47729c219c35dde2d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cf7c4d1f3415c86cf4a327da389d94f69a0e8f7a3bd84d933a42382aa9c33c86"

  strings:
    $s1 = "function _HBl2(s) {var _Fr9 = new Date();_Fr9.setUTCFullYear(\"2003\");if (_Fr9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _HBl2(s) {var _Fr9 = new Date();_Fr9.setUTCFullYear(\"2003\");if (_Fr9.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _SPu2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}