rule sig_20161205_42cae4305d0dff81d7763f81c1488706 {
  meta:
    description = "datamaliciousorder - file 20161205_42cae4305d0dff81d7763f81c1488706.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a947ae869dc4011214847a0d2f265a91617cc769073b9c7d249dd0239f7e4422"

  strings:
    $s1 = "function _Fc3(s) {var _XZh1 = new Date();_XZh1.setUTCFullYear(\"2003\");if (_XZh1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Fc3(s) {var _XZh1 = new Date();_XZh1.setUTCFullYear(\"2003\");if (_XZh1.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Fx5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}