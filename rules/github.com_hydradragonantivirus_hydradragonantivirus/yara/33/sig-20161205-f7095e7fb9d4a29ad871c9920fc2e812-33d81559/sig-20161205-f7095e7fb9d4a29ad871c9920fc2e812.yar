rule sig_20161205_f7095e7fb9d4a29ad871c9920fc2e812 {
  meta:
    description = "datamaliciousorder - file 20161205_f7095e7fb9d4a29ad871c9920fc2e812.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adbf9fef3c40d84cfe1d5c3b9caa8cab64ea61bcd64825a74f4ddb30cbae502e"

  strings:
    $s1 = "function _Zs6(s) {var _KFq2 = new Date();_KFq2.setUTCFullYear(\"2003\");if (_KFq2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Zs6(s) {var _KFq2 = new Date();_KFq2.setUTCFullYear(\"2003\");if (_KFq2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _ZHh4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}