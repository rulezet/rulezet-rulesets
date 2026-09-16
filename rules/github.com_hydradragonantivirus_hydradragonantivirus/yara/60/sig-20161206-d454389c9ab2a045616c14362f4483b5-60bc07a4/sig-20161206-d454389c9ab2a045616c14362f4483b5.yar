rule sig_20161206_d454389c9ab2a045616c14362f4483b5 {
  meta:
    description = "datamaliciousorder - file 20161206_d454389c9ab2a045616c14362f4483b5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3ed3b42ac28abec0cfcf8613e8ffba37149f60de87fe65614428272c56e0cdff"

  strings:
    $s1 = "function _Qs2(s) {var _Vm0 = new Date();_Vm0.setUTCFullYear(\"2003\");if (_Vm0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Qs2(s) {var _Vm0 = new Date();_Vm0.setUTCFullYear(\"2003\");if (_Vm0.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _ZEu2(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}