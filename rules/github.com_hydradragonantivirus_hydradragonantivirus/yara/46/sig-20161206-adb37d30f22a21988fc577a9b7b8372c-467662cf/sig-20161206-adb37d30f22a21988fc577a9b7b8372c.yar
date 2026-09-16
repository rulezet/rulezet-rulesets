rule sig_20161206_adb37d30f22a21988fc577a9b7b8372c {
  meta:
    description = "datamaliciousorder - file 20161206_adb37d30f22a21988fc577a9b7b8372c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "133344b3d13f72454a94ec45f6ae810240e129fb44db0adbbcf083417f21ef53"

  strings:
    $s1 = "function _AYw5(s) {var _GDj5 = new Date();_GDj5.setUTCFullYear(\"2003\");if (_GDj5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _AYw5(s) {var _GDj5 = new Date();_GDj5.setUTCFullYear(\"2003\");if (_GDj5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _BVg8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}