rule sig_20161206_1965f000e0ba32c25e37cbf7af10755f {
  meta:
    description = "datamaliciousorder - file 20161206_1965f000e0ba32c25e37cbf7af10755f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7c19d1be79639b23c0dfa65341ca20c7b25e6caa9be5a81c61a67ff5a8e44d9"

  strings:
    $s1 = "function _Xk0(s) {var _Jz0 = new Date();_Jz0.setUTCFullYear(\"2003\");if (_Jz0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Xk0(s) {var _Jz0 = new Date();_Jz0.setUTCFullYear(\"2003\");if (_Jz0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Ib7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}