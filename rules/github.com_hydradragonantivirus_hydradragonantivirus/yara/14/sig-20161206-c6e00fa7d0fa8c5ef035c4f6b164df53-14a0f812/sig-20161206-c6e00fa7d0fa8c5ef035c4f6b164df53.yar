rule sig_20161206_c6e00fa7d0fa8c5ef035c4f6b164df53 {
  meta:
    description = "datamaliciousorder - file 20161206_c6e00fa7d0fa8c5ef035c4f6b164df53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d56ddb5545f0ba5aee64885915fc7da0ee05ef843deb12af218b05bc52c993c4"

  strings:
    $s1 = "function _IOv3(s) {var _QNh5 = new Date();_QNh5.setUTCFullYear(\"2003\");if (_QNh5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _IOv3(s) {var _QNh5 = new Date();_QNh5.setUTCFullYear(\"2003\");if (_QNh5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _PYw0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}