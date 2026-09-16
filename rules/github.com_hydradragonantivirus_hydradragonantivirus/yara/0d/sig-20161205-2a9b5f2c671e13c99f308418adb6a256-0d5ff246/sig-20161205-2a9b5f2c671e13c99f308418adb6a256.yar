rule sig_20161205_2a9b5f2c671e13c99f308418adb6a256 {
  meta:
    description = "datamaliciousorder - file 20161205_2a9b5f2c671e13c99f308418adb6a256.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d772e84be65d33f112b4ffacdb0cef979188a2d5f5005b8e4ed76397afdf1fb7"

  strings:
    $s1 = "function _IGx4(s) {var _SBe6 = new Date();_SBe6.setUTCFullYear(\"2003\");if (_SBe6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _IGx4(s) {var _SBe6 = new Date();_SBe6.setUTCFullYear(\"2003\");if (_SBe6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ko7(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}