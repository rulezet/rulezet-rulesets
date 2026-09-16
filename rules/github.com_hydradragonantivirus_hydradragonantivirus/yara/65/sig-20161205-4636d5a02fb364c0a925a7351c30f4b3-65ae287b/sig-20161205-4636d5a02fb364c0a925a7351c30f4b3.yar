rule sig_20161205_4636d5a02fb364c0a925a7351c30f4b3 {
  meta:
    description = "datamaliciousorder - file 20161205_4636d5a02fb364c0a925a7351c30f4b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33472f14f87b085624efc0c5de63d59ea669095c30088751dbc2ab98179a8544"

  strings:
    $s1 = "function _Jg6(s) {var _Ns3 = new Date();_Ns3.setUTCFullYear(\"2003\");if (_Ns3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Jg6(s) {var _Ns3 = new Date();_Ns3.setUTCFullYear(\"2003\");if (_Ns3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Pt2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}