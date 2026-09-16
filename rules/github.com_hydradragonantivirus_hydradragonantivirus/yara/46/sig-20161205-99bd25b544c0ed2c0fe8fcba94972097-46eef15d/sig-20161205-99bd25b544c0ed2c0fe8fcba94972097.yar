rule sig_20161205_99bd25b544c0ed2c0fe8fcba94972097 {
  meta:
    description = "datamaliciousorder - file 20161205_99bd25b544c0ed2c0fe8fcba94972097.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "18e2411889805d8f6e6f328d93e39997e102c75ab6db70591c9a584364ba7c2c"

  strings:
    $s1 = "function _DOf5(s) {var _Fl4 = new Date();_Fl4.setUTCFullYear(\"2003\");if (_Fl4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _DOf5(s) {var _Fl4 = new Date();_Fl4.setUTCFullYear(\"2003\");if (_Fl4.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Gq9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}