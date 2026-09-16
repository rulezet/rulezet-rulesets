rule sig_20161206_141502e5957b78ba55fc2a9f88f5264a {
  meta:
    description = "datamaliciousorder - file 20161206_141502e5957b78ba55fc2a9f88f5264a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68d9ab6f52be25a08723104b3dbc2232c13229b961041bec59c2aadeee278d0e"

  strings:
    $s1 = "function _Hy2(s) {var _Dj5 = new Date();_Dj5.setUTCFullYear(\"2003\");if (_Dj5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Hy2(s) {var _Dj5 = new Date();_Dj5.setUTCFullYear(\"2003\");if (_Dj5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _ZWw8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}