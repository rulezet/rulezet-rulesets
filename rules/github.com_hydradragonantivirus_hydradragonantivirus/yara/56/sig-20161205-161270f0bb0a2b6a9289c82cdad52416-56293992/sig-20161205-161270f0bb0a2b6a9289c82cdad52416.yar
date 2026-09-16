rule sig_20161205_161270f0bb0a2b6a9289c82cdad52416 {
  meta:
    description = "datamaliciousorder - file 20161205_161270f0bb0a2b6a9289c82cdad52416.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a229dda8c02000610e88605f13f56b69799f77e6130448edc297db168290838b"

  strings:
    $s1 = "function _Lf3(s) {var _UEv9 = new Date();_UEv9.setUTCFullYear(\"2003\");if (_UEv9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Lf3(s) {var _UEv9 = new Date();_UEv9.setUTCFullYear(\"2003\");if (_UEv9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Lw5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}