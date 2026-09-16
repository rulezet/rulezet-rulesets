rule sig_20161205_0de6256abfe50c7e0298c7c3dfa57bd9 {
  meta:
    description = "datamaliciousorder - file 20161205_0de6256abfe50c7e0298c7c3dfa57bd9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9cd84bc91d03ed942edf34f7cb0f4d8fadd2c5060d3e58d03e399aba44e1f862"

  strings:
    $s1 = "function _Wu3(s) {var _Nu3 = new Date();_Nu3.setUTCFullYear(\"2003\");if (_Nu3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Wu3(s) {var _Nu3 = new Date();_Nu3.setUTCFullYear(\"2003\");if (_Nu3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _DKc4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}