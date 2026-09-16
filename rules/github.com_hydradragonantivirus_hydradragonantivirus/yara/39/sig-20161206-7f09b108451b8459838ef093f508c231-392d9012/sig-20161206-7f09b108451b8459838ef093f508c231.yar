rule sig_20161206_7f09b108451b8459838ef093f508c231 {
  meta:
    description = "datamaliciousorder - file 20161206_7f09b108451b8459838ef093f508c231.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e497af668dd42ff98644c6c94b77e22a6d2e73f29159098f3d8a34210a6e871a"

  strings:
    $s1 = "function _HRm6(s) {var _NMd9 = new Date();_NMd9.setUTCFullYear(\"2003\");if (_NMd9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _HRm6(s) {var _NMd9 = new Date();_NMd9.setUTCFullYear(\"2003\");if (_NMd9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _ENv6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}