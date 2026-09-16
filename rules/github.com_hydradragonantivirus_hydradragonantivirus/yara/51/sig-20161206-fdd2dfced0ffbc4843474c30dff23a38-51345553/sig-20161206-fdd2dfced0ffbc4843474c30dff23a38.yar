rule sig_20161206_fdd2dfced0ffbc4843474c30dff23a38 {
  meta:
    description = "datamaliciousorder - file 20161206_fdd2dfced0ffbc4843474c30dff23a38.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "52ab04f3e2eaf148cddc2a4f459029984d4f1c77fc0b71c181fa4395e6c67163"

  strings:
    $s1 = "function _JZb1(s) {var _BHg3 = new Date();_BHg3.setUTCFullYear(\"2003\");if (_BHg3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _JZb1(s) {var _BHg3 = new Date();_BHg3.setUTCFullYear(\"2003\");if (_BHg3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _WIb3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}