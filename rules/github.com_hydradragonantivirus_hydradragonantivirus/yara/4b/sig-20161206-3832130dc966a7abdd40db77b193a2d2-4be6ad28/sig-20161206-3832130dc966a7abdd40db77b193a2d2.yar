rule sig_20161206_3832130dc966a7abdd40db77b193a2d2 {
  meta:
    description = "datamaliciousorder - file 20161206_3832130dc966a7abdd40db77b193a2d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9460639d8fd1ece8e6ad10546c75f1789851a0bfdc6f23a1e3e8488373b2cb91"

  strings:
    $s1 = "function _Ad6(s) {var _VUc6 = new Date();_VUc6.setUTCFullYear(\"2003\");if (_VUc6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Ad6(s) {var _VUc6 = new Date();_VUc6.setUTCFullYear(\"2003\");if (_VUc6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Cn8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}