rule sig_20161205_909e67e43d2e6daceb1cbbf6e7fe1808 {
  meta:
    description = "datamaliciousorder - file 20161205_909e67e43d2e6daceb1cbbf6e7fe1808.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5216ad8e94cb8638e23846b074943b4696d8bf3260412a25b9a6b592543571f"

  strings:
    $s1 = "function _YSi1(s) {var _Io8 = new Date();_Io8.setUTCFullYear(\"2003\");if (_Io8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _YSi1(s) {var _Io8 = new Date();_Io8.setUTCFullYear(\"2003\");if (_Io8.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _PDu0(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}