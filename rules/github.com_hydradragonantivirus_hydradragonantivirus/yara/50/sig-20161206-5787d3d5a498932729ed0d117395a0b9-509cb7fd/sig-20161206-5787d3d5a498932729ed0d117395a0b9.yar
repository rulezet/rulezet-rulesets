rule sig_20161206_5787d3d5a498932729ed0d117395a0b9 {
  meta:
    description = "datamaliciousorder - file 20161206_5787d3d5a498932729ed0d117395a0b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9167b4cc52ec98b884f1c2316de498656c0280f0bae39a4f0582777e6ab62a22"

  strings:
    $s1 = "function _Uw4(s) {var _GDk6 = new Date();_GDk6.setUTCFullYear(\"2003\");if (_GDk6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Uw4(s) {var _GDk6 = new Date();_GDk6.setUTCFullYear(\"2003\");if (_GDk6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Yl3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}