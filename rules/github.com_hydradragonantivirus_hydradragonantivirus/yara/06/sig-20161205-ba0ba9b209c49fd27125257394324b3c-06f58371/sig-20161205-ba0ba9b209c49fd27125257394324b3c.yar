rule sig_20161205_ba0ba9b209c49fd27125257394324b3c {
  meta:
    description = "datamaliciousorder - file 20161205_ba0ba9b209c49fd27125257394324b3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f500c754c0c1fded5f81b18c51619d0a43b0adaed87cfc7fe9ab85407f8e5058"

  strings:
    $s1 = "function _Ik5(s) {var _Hz0 = new Date();_Hz0.setUTCFullYear(\"2003\");if (_Hz0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Ik5(s) {var _Hz0 = new Date();_Hz0.setUTCFullYear(\"2003\");if (_Hz0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Xk0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}