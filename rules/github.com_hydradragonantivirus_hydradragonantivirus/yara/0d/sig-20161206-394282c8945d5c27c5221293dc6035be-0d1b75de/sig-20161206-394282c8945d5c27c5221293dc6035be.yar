rule sig_20161206_394282c8945d5c27c5221293dc6035be {
  meta:
    description = "datamaliciousorder - file 20161206_394282c8945d5c27c5221293dc6035be.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d0873f6e1638610b1acba92b9b3ee0ea9cf6f5a487c945f93c9091e3e5e6df3"

  strings:
    $s1 = "function _Hp4(s) {var _BRx6 = new Date();_BRx6.setUTCFullYear(\"2003\");if (_BRx6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Hp4(s) {var _BRx6 = new Date();_BRx6.setUTCFullYear(\"2003\");if (_BRx6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _OWb8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}