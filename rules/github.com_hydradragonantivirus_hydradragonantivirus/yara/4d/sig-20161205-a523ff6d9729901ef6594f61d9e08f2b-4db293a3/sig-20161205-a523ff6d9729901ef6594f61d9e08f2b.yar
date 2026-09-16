rule sig_20161205_a523ff6d9729901ef6594f61d9e08f2b {
  meta:
    description = "datamaliciousorder - file 20161205_a523ff6d9729901ef6594f61d9e08f2b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf10ba8710451e807475d94ae9457af2f85e01e6f0586d6a6a37d4b87cd5539d"

  strings:
    $s1 = "function _Hj8(s) {var _Ey1 = new Date();_Ey1.setUTCFullYear(\"2003\");if (_Ey1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Hj8(s) {var _Ey1 = new Date();_Ey1.setUTCFullYear(\"2003\");if (_Ey1.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _AQj7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}