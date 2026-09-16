rule sig_20161205_2e8d8f07a75ef1d28ece284e26e4641a {
  meta:
    description = "datamaliciousorder - file 20161205_2e8d8f07a75ef1d28ece284e26e4641a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d81c1609ecd715358618430ed24417e3b8f8122ecd2d1f63d500e909633b265"

  strings:
    $s1 = "function _MOk0(s) {var _IFp1 = new Date();_IFp1.setUTCFullYear(\"2003\");if (_IFp1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _MOk0(s) {var _IFp1 = new Date();_IFp1.setUTCFullYear(\"2003\");if (_IFp1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _OKx3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}