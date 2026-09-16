rule sig_20161206_b28facbfabb11fd661ae28557de59dbd {
  meta:
    description = "datamaliciousorder - file 20161206_b28facbfabb11fd661ae28557de59dbd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9d5172c9d2332daefd606ccdec54e9bc8d6432259310f10b3535599f62300a8b"

  strings:
    $s1 = "function _Zd5(s) {var _BOh6 = new Date();_BOh6.setUTCFullYear(\"2003\");if (_BOh6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Zd5(s) {var _BOh6 = new Date();_BOh6.setUTCFullYear(\"2003\");if (_BOh6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Cm9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}