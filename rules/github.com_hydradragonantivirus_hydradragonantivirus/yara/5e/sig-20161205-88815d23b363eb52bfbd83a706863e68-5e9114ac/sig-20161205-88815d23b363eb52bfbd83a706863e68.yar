rule sig_20161205_88815d23b363eb52bfbd83a706863e68 {
  meta:
    description = "datamaliciousorder - file 20161205_88815d23b363eb52bfbd83a706863e68.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a00f5af6b01dad81c422a842a8fa1e92eb18f47867cc5692a0e8b8aaf63dc63b"

  strings:
    $s1 = "function _Mn4(s) {var _ETr8 = new Date();_ETr8.setUTCFullYear(\"2003\");if (_ETr8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Mn4(s) {var _ETr8 = new Date();_ETr8.setUTCFullYear(\"2003\");if (_ETr8.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Kv4(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}