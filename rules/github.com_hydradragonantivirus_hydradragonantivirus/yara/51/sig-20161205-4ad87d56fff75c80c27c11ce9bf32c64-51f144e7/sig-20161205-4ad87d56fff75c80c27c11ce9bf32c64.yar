rule sig_20161205_4ad87d56fff75c80c27c11ce9bf32c64 {
  meta:
    description = "datamaliciousorder - file 20161205_4ad87d56fff75c80c27c11ce9bf32c64.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e70c2e19c51866e6c92d2cbb2a9c43258fc1fc2696ca6c6aeafda90e408e914f"

  strings:
    $s1 = "function _Dt3(s) {var _FXp2 = new Date();_FXp2.setUTCFullYear(\"2003\");if (_FXp2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Dt3(s) {var _FXp2 = new Date();_FXp2.setUTCFullYear(\"2003\");if (_FXp2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _CXy2(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}