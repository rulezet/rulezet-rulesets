rule sig_20161205_06abd02d89e8ad422b9e8aa9a64f0a1c {
  meta:
    description = "datamaliciousorder - file 20161205_06abd02d89e8ad422b9e8aa9a64f0a1c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "39b849695b271e20c8643870962b4e26e1d58fc737f9c8a90f406679c07a7b42"

  strings:
    $s1 = "function _MBd1(s) {var _Yq6 = new Date();_Yq6.setUTCFullYear(\"2003\");if (_Yq6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _MBd1(s) {var _Yq6 = new Date();_Yq6.setUTCFullYear(\"2003\");if (_Yq6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _NHj9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}