rule sig_20161205_29c918ed61a5a89d0e4845b612b766bf {
  meta:
    description = "datamaliciousorder - file 20161205_29c918ed61a5a89d0e4845b612b766bf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4488d031d6b4c0a2a72e51caf81fd1bb2483f0ef38d4ca278eef58b635994b5e"

  strings:
    $s1 = "function _Dl0(s) {var _PId7 = new Date();_PId7.setUTCFullYear(\"2003\");if (_PId7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Dl0(s) {var _PId7 = new Date();_PId7.setUTCFullYear(\"2003\");if (_PId7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _YPd5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}