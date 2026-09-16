rule sig_20161205_5760d9b34bdaac1c4e67f59d3354af6d {
  meta:
    description = "datamaliciousorder - file 20161205_5760d9b34bdaac1c4e67f59d3354af6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "45fca0ca57f555c701f1f7ecaeb9bf55549d7bf8664955781e32c438fb7da429"

  strings:
    $s1 = "function _Bv4(s) {var _Ye3 = new Date();_Ye3.setUTCFullYear(\"2003\");if (_Ye3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Bv4(s) {var _Ye3 = new Date();_Ye3.setUTCFullYear(\"2003\");if (_Ye3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _HRg6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}