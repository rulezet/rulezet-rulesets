rule sig_20161205_85a5cbbebc6249b31c3c155a21a4ad8b {
  meta:
    description = "datamaliciousorder - file 20161205_85a5cbbebc6249b31c3c155a21a4ad8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "365494c89bf94d1f579b2480c423c9bb1957b26c66258d714fe175ed39103535"

  strings:
    $s1 = "function _Qs3(s) {var _OOi2 = new Date();_OOi2.setUTCFullYear(\"2003\");if (_OOi2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Qs3(s) {var _OOi2 = new Date();_OOi2.setUTCFullYear(\"2003\");if (_OOi2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Df0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}