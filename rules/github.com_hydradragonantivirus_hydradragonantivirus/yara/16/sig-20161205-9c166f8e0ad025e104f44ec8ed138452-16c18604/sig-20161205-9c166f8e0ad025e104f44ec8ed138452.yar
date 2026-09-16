rule sig_20161205_9c166f8e0ad025e104f44ec8ed138452 {
  meta:
    description = "datamaliciousorder - file 20161205_9c166f8e0ad025e104f44ec8ed138452.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1eb9699a0ec74076b08646b1c2b1811ddd60f88aa622a48dae39c34e96cc89b2"

  strings:
    $s1 = "function _DYb7(s) {var _Mo1 = new Date();_Mo1.setUTCFullYear(\"2003\");if (_Mo1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _DYb7(s) {var _Mo1 = new Date();_Mo1.setUTCFullYear(\"2003\");if (_Mo1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _BFc3(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}