rule sig_20161205_c4093245ce0af21e42750d27b5be3a09 {
  meta:
    description = "datamaliciousorder - file 20161205_c4093245ce0af21e42750d27b5be3a09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0fc0383ec1f8e77278d00a4e0256bf0b8ad990eb14f18eecd4df61a577295606"

  strings:
    $s1 = "function _IPj2(s) {var _Uv7 = new Date();_Uv7.setUTCFullYear(\"2003\");if (_Uv7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _IPj2(s) {var _Uv7 = new Date();_Uv7.setUTCFullYear(\"2003\");if (_Uv7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Nb5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}