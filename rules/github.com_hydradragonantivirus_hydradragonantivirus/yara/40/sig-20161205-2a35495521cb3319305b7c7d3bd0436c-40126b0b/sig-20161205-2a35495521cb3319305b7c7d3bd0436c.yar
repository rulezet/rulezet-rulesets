rule sig_20161205_2a35495521cb3319305b7c7d3bd0436c {
  meta:
    description = "datamaliciousorder - file 20161205_2a35495521cb3319305b7c7d3bd0436c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6710934862afed212ff88b4094a16e92450e1004615bdb241fcb61dd4bd09795"

  strings:
    $s1 = "function _RFh3(s) {var _Ve5 = new Date();_Ve5.setUTCFullYear(\"2003\");if (_Ve5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _RFh3(s) {var _Ve5 = new Date();_Ve5.setUTCFullYear(\"2003\");if (_Ve5.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _QDr3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}