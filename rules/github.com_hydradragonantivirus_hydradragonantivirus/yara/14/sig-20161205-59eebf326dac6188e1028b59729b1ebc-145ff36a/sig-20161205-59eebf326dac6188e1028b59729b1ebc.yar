rule sig_20161205_59eebf326dac6188e1028b59729b1ebc {
  meta:
    description = "datamaliciousorder - file 20161205_59eebf326dac6188e1028b59729b1ebc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07a9bda8a5de7edba5e1cf0f53c754b9c7f2a313a3e95018a374c27a1113b7cf"

  strings:
    $s1 = "function _Kx6(s) {var _WNx0 = new Date();_WNx0.setUTCFullYear(\"2003\");if (_WNx0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Kx6(s) {var _WNx0 = new Date();_WNx0.setUTCFullYear(\"2003\");if (_WNx0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _XIt1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}