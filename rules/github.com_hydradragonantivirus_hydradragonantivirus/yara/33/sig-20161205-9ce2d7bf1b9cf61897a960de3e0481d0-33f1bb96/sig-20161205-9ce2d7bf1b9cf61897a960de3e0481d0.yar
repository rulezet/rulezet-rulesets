rule sig_20161205_9ce2d7bf1b9cf61897a960de3e0481d0 {
  meta:
    description = "datamaliciousorder - file 20161205_9ce2d7bf1b9cf61897a960de3e0481d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fad379ba7f9d1b7e2d8efd4f92e622e386e56e4a05499d4a0c80e05072a5d355"

  strings:
    $s1 = "function _Gi0(s) {var _Et3 = new Date();_Et3.setUTCFullYear(\"2003\");if (_Et3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Gi0(s) {var _Et3 = new Date();_Et3.setUTCFullYear(\"2003\");if (_Et3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Sr7(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}