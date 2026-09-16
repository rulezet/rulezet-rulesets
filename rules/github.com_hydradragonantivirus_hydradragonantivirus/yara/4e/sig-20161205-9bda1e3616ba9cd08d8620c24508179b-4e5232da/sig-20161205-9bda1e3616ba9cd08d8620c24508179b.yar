rule sig_20161205_9bda1e3616ba9cd08d8620c24508179b {
  meta:
    description = "datamaliciousorder - file 20161205_9bda1e3616ba9cd08d8620c24508179b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56b9e83d98a8e22eade9da78e879a2786bc6bb5ffdca1f49b4e6533a87d619aa"

  strings:
    $s1 = "function _Yw3(s) {var _Jg2 = new Date();_Jg2.setUTCFullYear(\"2003\");if (_Jg2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Yw3(s) {var _Jg2 = new Date();_Jg2.setUTCFullYear(\"2003\");if (_Jg2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _OGp9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}