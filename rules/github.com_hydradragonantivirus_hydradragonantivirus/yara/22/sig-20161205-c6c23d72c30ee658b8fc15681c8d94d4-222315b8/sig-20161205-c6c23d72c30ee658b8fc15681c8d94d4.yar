rule sig_20161205_c6c23d72c30ee658b8fc15681c8d94d4 {
  meta:
    description = "datamaliciousorder - file 20161205_c6c23d72c30ee658b8fc15681c8d94d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "382cbd5e6ac0ae5ddb6876d296349f604e576c1604258c50403734ec660a8f6d"

  strings:
    $s1 = "function _Tc0(s) {var _Nj4 = new Date();_Nj4.setUTCFullYear(\"2003\");if (_Nj4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Tc0(s) {var _Nj4 = new Date();_Nj4.setUTCFullYear(\"2003\");if (_Nj4.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Xd5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}