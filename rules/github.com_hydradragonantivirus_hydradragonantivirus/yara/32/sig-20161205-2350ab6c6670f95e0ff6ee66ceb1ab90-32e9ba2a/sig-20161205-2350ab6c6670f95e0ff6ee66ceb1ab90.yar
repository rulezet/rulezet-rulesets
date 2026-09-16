rule sig_20161205_2350ab6c6670f95e0ff6ee66ceb1ab90 {
  meta:
    description = "datamaliciousorder - file 20161205_2350ab6c6670f95e0ff6ee66ceb1ab90.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8560921c10915ac5ce945b0590c5aee65512490cfff2377fddfd46a5b8430bc9"

  strings:
    $s1 = "function _VJa8(s) {var _JAr1 = new Date();_JAr1.setUTCFullYear(\"2003\");if (_JAr1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _VJa8(s) {var _JAr1 = new Date();_JAr1.setUTCFullYear(\"2003\");if (_JAr1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Mn6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}