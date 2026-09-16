rule sig_20161205_3dc39e21dcfdaea0530ccb27aa6d9c04 {
  meta:
    description = "datamaliciousorder - file 20161205_3dc39e21dcfdaea0530ccb27aa6d9c04.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27e827d35d877ae03da6c79be9ace5c22304c3b55bf414b9dee81c687e3aea25"

  strings:
    $s1 = "function _Bl5(s) {var _Al5 = new Date();_Al5.setUTCFullYear(\"2003\");if (_Al5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Bl5(s) {var _Al5 = new Date();_Al5.setUTCFullYear(\"2003\");if (_Al5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _HQw6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}