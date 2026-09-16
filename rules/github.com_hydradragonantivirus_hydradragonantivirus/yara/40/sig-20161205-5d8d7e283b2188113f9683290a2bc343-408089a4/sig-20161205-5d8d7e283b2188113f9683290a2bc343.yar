rule sig_20161205_5d8d7e283b2188113f9683290a2bc343 {
  meta:
    description = "datamaliciousorder - file 20161205_5d8d7e283b2188113f9683290a2bc343.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "851708a74ef9d8eb08d1f65467ddb2cf9d8b6ae94f19d8ca11151112866e0a2c"

  strings:
    $s1 = "function _Qn0(s) {var _Sp9 = new Date();_Sp9.setUTCFullYear(\"2003\");if (_Sp9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Qn0(s) {var _Sp9 = new Date();_Sp9.setUTCFullYear(\"2003\");if (_Sp9.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _FWl7(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}