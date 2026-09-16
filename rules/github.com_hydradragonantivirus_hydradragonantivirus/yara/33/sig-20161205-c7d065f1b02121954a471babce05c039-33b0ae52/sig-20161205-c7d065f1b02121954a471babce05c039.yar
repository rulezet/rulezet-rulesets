rule sig_20161205_c7d065f1b02121954a471babce05c039 {
  meta:
    description = "datamaliciousorder - file 20161205_c7d065f1b02121954a471babce05c039.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9fc3fd1186892ab0dcc145262e5293e33148f439e9540799ba6b917b94a259bd"

  strings:
    $s1 = "function _JTr2(s) {var _KLd5 = new Date();_KLd5.setUTCFullYear(\"2003\");if (_KLd5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _JTr2(s) {var _KLd5 = new Date();_KLd5.setUTCFullYear(\"2003\");if (_KLd5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _RZb6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}