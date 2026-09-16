rule sig_20161205_6fa993a1d3f1bc34d5893e622d80c01c {
  meta:
    description = "datamaliciousorder - file 20161205_6fa993a1d3f1bc34d5893e622d80c01c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b8f8fa13484b3b09a926cfc36182966867232d49f00e0d0f63766961aa61cf54"

  strings:
    $s1 = "function _ERu0(s) {var _Qo2 = new Date();_Qo2.setUTCFullYear(\"2003\");if (_Qo2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _ERu0(s) {var _Qo2 = new Date();_Qo2.setUTCFullYear(\"2003\");if (_Qo2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _TSu9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}