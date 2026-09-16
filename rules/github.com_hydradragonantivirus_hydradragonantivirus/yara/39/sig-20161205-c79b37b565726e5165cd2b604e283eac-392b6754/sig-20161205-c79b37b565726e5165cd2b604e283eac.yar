rule sig_20161205_c79b37b565726e5165cd2b604e283eac {
  meta:
    description = "datamaliciousorder - file 20161205_c79b37b565726e5165cd2b604e283eac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f9fa98f5085d2c6dabc6c07b282ef57ea049a61861495b400b4278a9b83a0d7"

  strings:
    $s1 = "function _ZZr7(s) {var _La7 = new Date();_La7.setUTCFullYear(\"2003\");if (_La7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _ZZr7(s) {var _La7 = new Date();_La7.setUTCFullYear(\"2003\");if (_La7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Aj8(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}