rule sig_20161206_3473109ffbebbaacfc54bb975598726b {
  meta:
    description = "datamaliciousorder - file 20161206_3473109ffbebbaacfc54bb975598726b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90915b55280f6348c36e6eeca2fdc08ddb48022449923842f1d2348788877332"

  strings:
    $s1 = "function _Kx2(s) {var _PBv9 = new Date();_PBv9.setUTCFullYear(\"2003\");if (_PBv9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Kx2(s) {var _PBv9 = new Date();_PBv9.setUTCFullYear(\"2003\");if (_PBv9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _FJu2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}