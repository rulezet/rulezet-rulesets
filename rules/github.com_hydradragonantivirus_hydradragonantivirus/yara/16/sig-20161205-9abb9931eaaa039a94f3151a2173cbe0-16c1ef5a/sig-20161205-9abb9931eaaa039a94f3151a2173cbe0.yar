rule sig_20161205_9abb9931eaaa039a94f3151a2173cbe0 {
  meta:
    description = "datamaliciousorder - file 20161205_9abb9931eaaa039a94f3151a2173cbe0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "df72e70634aed4c9f17205f27271643b66e6b3c6b82b768004299d212d09e5ca"

  strings:
    $s1 = "function _STe8(s) {var _Cu6 = new Date();_Cu6.setUTCFullYear(\"2003\");if (_Cu6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _STe8(s) {var _Cu6 = new Date();_Cu6.setUTCFullYear(\"2003\");if (_Cu6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Dz9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}