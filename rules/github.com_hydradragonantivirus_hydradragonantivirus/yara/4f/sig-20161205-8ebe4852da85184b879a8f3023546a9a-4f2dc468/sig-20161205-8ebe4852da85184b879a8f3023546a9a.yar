rule sig_20161205_8ebe4852da85184b879a8f3023546a9a {
  meta:
    description = "datamaliciousorder - file 20161205_8ebe4852da85184b879a8f3023546a9a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d118201776d99325faacc00dd11e1f7853f93527699cca039a5d1996fdd9c7e2"

  strings:
    $s1 = "function _GBm2(s) {var _Ya1 = new Date();_Ya1.setUTCFullYear(\"2003\");if (_Ya1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _GBm2(s) {var _Ya1 = new Date();_Ya1.setUTCFullYear(\"2003\");if (_Ya1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _VNo7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}