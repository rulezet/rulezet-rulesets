rule sig_20161205_6c857cb6008bdc2d72f79c552b811d00 {
  meta:
    description = "datamaliciousorder - file 20161205_6c857cb6008bdc2d72f79c552b811d00.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b277c78160f675724d0d65eec4d2090b512f8cc928aa33784d119746ec42363"

  strings:
    $s1 = "function _Ol4(s) {var _FBn4 = new Date();_FBn4.setUTCFullYear(\"2003\");if (_FBn4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ol4(s) {var _FBn4 = new Date();_FBn4.setUTCFullYear(\"2003\");if (_FBn4.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _YYp4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}