rule sig_20161205_263aff6932e442937d71fd5b9780fe8f {
  meta:
    description = "datamaliciousorder - file 20161205_263aff6932e442937d71fd5b9780fe8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10cc5f8c274f474eff53937efb8271167e1d066843e4ff4e2bba72a50b0472d9"

  strings:
    $s1 = "function _DAv2(s) {var _JSs0 = new Date();_JSs0.setUTCFullYear(\"2003\");if (_JSs0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _DAv2(s) {var _JSs0 = new Date();_JSs0.setUTCFullYear(\"2003\");if (_JSs0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _EUj0(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}