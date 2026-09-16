rule sig_20161205_98f695d11819810504d51b8b95e8ade2 {
  meta:
    description = "datamaliciousorder - file 20161205_98f695d11819810504d51b8b95e8ade2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "490134b1d87c10c10c0000a5f9261efeb82320e7d1beb7432a92f3e2275ee31b"

  strings:
    $s1 = "function _DPv2(s) {var _GFm6 = new Date();_GFm6.setUTCFullYear(\"2003\");if (_GFm6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _DPv2(s) {var _GFm6 = new Date();_GFm6.setUTCFullYear(\"2003\");if (_GFm6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Lq6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}