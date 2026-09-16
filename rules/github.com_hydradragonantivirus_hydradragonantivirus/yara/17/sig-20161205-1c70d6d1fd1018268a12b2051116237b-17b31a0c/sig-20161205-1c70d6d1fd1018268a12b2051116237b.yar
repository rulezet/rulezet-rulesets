rule sig_20161205_1c70d6d1fd1018268a12b2051116237b {
  meta:
    description = "datamaliciousorder - file 20161205_1c70d6d1fd1018268a12b2051116237b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "720fdafd9121662f23233e851392a977c9dd9ed67703684ae7125b31ecb6d28b"

  strings:
    $s1 = "function _Pp5(s) {var _Fo4 = new Date();_Fo4.setUTCFullYear(\"2003\");if (_Fo4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Pp5(s) {var _Fo4 = new Date();_Fo4.setUTCFullYear(\"2003\");if (_Fo4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _ELf1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}