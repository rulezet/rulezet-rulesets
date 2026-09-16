rule sig_20161205_d64e7b55543d9dd82d066c3db61d1e81 {
  meta:
    description = "datamaliciousorder - file 20161205_d64e7b55543d9dd82d066c3db61d1e81.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81d676533d4be53e0dc2c050224754caae08cec2e8bf696fae3f245bdf239dbf"

  strings:
    $s1 = "function _IXc4(s) {var _Gp7 = new Date();_Gp7.setUTCFullYear(\"2003\");if (_Gp7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _IXc4(s) {var _Gp7 = new Date();_Gp7.setUTCFullYear(\"2003\");if (_Gp7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Vi0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}