rule sig_20161206_9b3e498e9d62599e4ea28ecdf45c8409 {
  meta:
    description = "datamaliciousorder - file 20161206_9b3e498e9d62599e4ea28ecdf45c8409.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f15c8e1db3fff702813b0f81c88e3a912bf04af45e1860a1b910de3bf7ccf3a5"

  strings:
    $s1 = "function _JSh8(s) {var _NMm3 = new Date();_NMm3.setUTCFullYear(\"2003\");if (_NMm3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _JSh8(s) {var _NMm3 = new Date();_NMm3.setUTCFullYear(\"2003\");if (_NMm3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _RVy7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}