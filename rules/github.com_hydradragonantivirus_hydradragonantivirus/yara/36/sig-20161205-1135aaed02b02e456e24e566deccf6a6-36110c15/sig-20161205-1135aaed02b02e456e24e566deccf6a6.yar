rule sig_20161205_1135aaed02b02e456e24e566deccf6a6 {
  meta:
    description = "datamaliciousorder - file 20161205_1135aaed02b02e456e24e566deccf6a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b6a47e2dfb954b96c8708e3056a60c7e728d86f408d4b122ac023e2cde84671"

  strings:
    $s1 = "function _Ia1(s) {var _LGy8 = new Date();_LGy8.setUTCFullYear(\"2003\");if (_LGy8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ia1(s) {var _LGy8 = new Date();_LGy8.setUTCFullYear(\"2003\");if (_LGy8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _By7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}