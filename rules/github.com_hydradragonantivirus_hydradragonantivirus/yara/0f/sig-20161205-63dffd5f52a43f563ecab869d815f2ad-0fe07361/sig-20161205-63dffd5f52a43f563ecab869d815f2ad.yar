rule sig_20161205_63dffd5f52a43f563ecab869d815f2ad {
  meta:
    description = "datamaliciousorder - file 20161205_63dffd5f52a43f563ecab869d815f2ad.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44a7c68c608d5ea86113f7ea9d7ee64185122d8534e8bd8f998e181ccff3fd97"

  strings:
    $s1 = "function _VWi4(s) {var _GVq1 = new Date();_GVq1.setUTCFullYear(\"2003\");if (_GVq1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _VWi4(s) {var _GVq1 = new Date();_GVq1.setUTCFullYear(\"2003\");if (_GVq1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Dk6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}