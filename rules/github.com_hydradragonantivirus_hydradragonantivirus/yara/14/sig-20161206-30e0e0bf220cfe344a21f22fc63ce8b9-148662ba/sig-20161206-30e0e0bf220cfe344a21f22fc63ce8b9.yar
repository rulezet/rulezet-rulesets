rule sig_20161206_30e0e0bf220cfe344a21f22fc63ce8b9 {
  meta:
    description = "datamaliciousorder - file 20161206_30e0e0bf220cfe344a21f22fc63ce8b9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7b4538a9b0ddf7c6f71956c9b61434493ffd15c01bbd0cc7123bf109c41829d"

  strings:
    $s1 = "function _NKe3(s) {var _LXi6 = new Date();_LXi6.setUTCFullYear(\"2003\");if (_LXi6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _NKe3(s) {var _LXi6 = new Date();_LXi6.setUTCFullYear(\"2003\");if (_LXi6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Fl1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}