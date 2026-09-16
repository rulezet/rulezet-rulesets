rule sig_20161205_75635f068b4c385488525da64ea5ab04 {
  meta:
    description = "datamaliciousorder - file 20161205_75635f068b4c385488525da64ea5ab04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58d3e1bd32ac2e743109c6d40414b2a1ce5e8786257b62a189534363021f78e5"

  strings:
    $s1 = "function _Zh0(s) {var _EPw0 = new Date();_EPw0.setUTCFullYear(\"2003\");if (_EPw0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Zh0(s) {var _EPw0 = new Date();_EPw0.setUTCFullYear(\"2003\");if (_EPw0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Ks9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}