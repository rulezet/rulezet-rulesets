rule sig_20161205_40b1beaa6c38e3823c4b45517d131dd2 {
  meta:
    description = "datamaliciousorder - file 20161205_40b1beaa6c38e3823c4b45517d131dd2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a14dcafd0948f0df6250dfa668188d82df5490a36033cbc89c3e5916473537e5"

  strings:
    $s1 = "function _VJr3(s) {var _MLa7 = new Date();_MLa7.setUTCFullYear(\"2003\");if (_MLa7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _VJr3(s) {var _MLa7 = new Date();_MLa7.setUTCFullYear(\"2003\");if (_MLa7.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _DBg9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}