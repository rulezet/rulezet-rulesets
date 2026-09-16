rule sig_20161205_cbc147974a2102f668617b456a3c8a67 {
  meta:
    description = "datamaliciousorder - file 20161205_cbc147974a2102f668617b456a3c8a67.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "31e4a2f11bf1c8fab5feab8c1e226ca7610c3c4a2b8b2cd8a146c4708f7ae019"

  strings:
    $s1 = "function _TRc0(s) {var _UXh0 = new Date();_UXh0.setUTCFullYear(\"2003\");if (_UXh0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _TRc0(s) {var _UXh0 = new Date();_UXh0.setUTCFullYear(\"2003\");if (_UXh0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Kl9(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}