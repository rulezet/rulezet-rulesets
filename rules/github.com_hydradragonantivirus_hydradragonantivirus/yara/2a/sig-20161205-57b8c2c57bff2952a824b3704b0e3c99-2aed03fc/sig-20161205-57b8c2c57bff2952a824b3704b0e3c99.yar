rule sig_20161205_57b8c2c57bff2952a824b3704b0e3c99 {
  meta:
    description = "datamaliciousorder - file 20161205_57b8c2c57bff2952a824b3704b0e3c99.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aeae9de7cbed7b32119383d63a9ee8639c4a42d9713cfdbc363af4b1519e2af1"

  strings:
    $s1 = "function _Uv7(s) {var _Zq1 = new Date();_Zq1.setUTCFullYear(\"2003\");if (_Zq1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Uv7(s) {var _Zq1 = new Date();_Zq1.setUTCFullYear(\"2003\");if (_Zq1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _PEi7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}