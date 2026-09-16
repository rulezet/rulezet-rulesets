rule sig_20161205_b8eccad9a872e968bf66b97b6e6837fe {
  meta:
    description = "datamaliciousorder - file 20161205_b8eccad9a872e968bf66b97b6e6837fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f01e9776d5a5f8d66a9251b025797bad19fb40a6c432ed2d4b643d1f2026733f"

  strings:
    $s1 = "function _Yr0(s) {var _PKr3 = new Date();_PKr3.setUTCFullYear(\"2003\");if (_PKr3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Yr0(s) {var _PKr3 = new Date();_PKr3.setUTCFullYear(\"2003\");if (_PKr3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ah8(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}