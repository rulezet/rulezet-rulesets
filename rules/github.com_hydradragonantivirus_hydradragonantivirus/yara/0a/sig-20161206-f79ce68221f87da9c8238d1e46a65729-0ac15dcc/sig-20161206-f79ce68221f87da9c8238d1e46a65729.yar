rule sig_20161206_f79ce68221f87da9c8238d1e46a65729 {
  meta:
    description = "datamaliciousorder - file 20161206_f79ce68221f87da9c8238d1e46a65729.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e655a240d19b1ef084e94dcaa5ecbd0b7130a1a3bb50b9d911babc920efb813a"

  strings:
    $s1 = "function _Mb3(s) {var _Am6 = new Date();_Am6.setUTCFullYear(\"2003\");if (_Am6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Mb3(s) {var _Am6 = new Date();_Am6.setUTCFullYear(\"2003\");if (_Am6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Hw3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}