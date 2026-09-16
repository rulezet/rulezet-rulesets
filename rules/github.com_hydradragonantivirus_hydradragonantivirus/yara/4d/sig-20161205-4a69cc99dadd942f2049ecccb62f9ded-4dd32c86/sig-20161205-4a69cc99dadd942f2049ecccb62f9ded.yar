rule sig_20161205_4a69cc99dadd942f2049ecccb62f9ded {
  meta:
    description = "datamaliciousorder - file 20161205_4a69cc99dadd942f2049ecccb62f9ded.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92053d027d66905fa70bced3616329905987f33a65862e5d6adee09d727df997"

  strings:
    $s1 = "function _FLf2(s) {var _NRc4 = new Date();_NRc4.setUTCFullYear(\"2003\");if (_NRc4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _FLf2(s) {var _NRc4 = new Date();_NRc4.setUTCFullYear(\"2003\");if (_NRc4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _MIy7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}