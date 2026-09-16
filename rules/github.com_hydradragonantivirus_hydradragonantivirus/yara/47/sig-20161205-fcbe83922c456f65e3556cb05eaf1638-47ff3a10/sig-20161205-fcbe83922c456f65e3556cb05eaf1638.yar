rule sig_20161205_fcbe83922c456f65e3556cb05eaf1638 {
  meta:
    description = "datamaliciousorder - file 20161205_fcbe83922c456f65e3556cb05eaf1638.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fe437887da54fc0976bc876f210d3007f7f8b0a4e3d6386923b2361ec3a2d43d"

  strings:
    $s1 = "function _GSb5(s) {var _BKx1 = new Date();_BKx1.setUTCFullYear(\"2003\");if (_BKx1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _GSb5(s) {var _BKx1 = new Date();_BKx1.setUTCFullYear(\"2003\");if (_BKx1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Uh3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}