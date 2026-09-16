rule sig_20161205_3030a6970348cbb57d00e985c8437e9b {
  meta:
    description = "datamaliciousorder - file 20161205_3030a6970348cbb57d00e985c8437e9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44fec9388c02bdfb1773aa095b8c3a084526c38d012c7650a5796cd3fca9687e"

  strings:
    $s1 = "function _Zl7(s) {var _CMl0 = new Date();_CMl0.setUTCFullYear(\"2003\");if (_CMl0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Zl7(s) {var _CMl0 = new Date();_CMl0.setUTCFullYear(\"2003\");if (_CMl0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Pi5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}