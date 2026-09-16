rule sig_20161205_e59dc1eed7665fff384be48684262c15 {
  meta:
    description = "datamaliciousorder - file 20161205_e59dc1eed7665fff384be48684262c15.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ee74722da78cb6f2909daa80bfb1382f0e6c6eb6d219f1ea87f1585a020c9c6"

  strings:
    $s1 = "function _PYz3(s) {var _TJd8 = new Date();_TJd8.setUTCFullYear(\"2003\");if (_TJd8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _PYz3(s) {var _TJd8 = new Date();_TJd8.setUTCFullYear(\"2003\");if (_TJd8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _FXj5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}