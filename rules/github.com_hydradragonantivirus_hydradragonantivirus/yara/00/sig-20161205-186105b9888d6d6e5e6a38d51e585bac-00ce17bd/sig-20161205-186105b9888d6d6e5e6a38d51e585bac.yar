rule sig_20161205_186105b9888d6d6e5e6a38d51e585bac {
  meta:
    description = "datamaliciousorder - file 20161205_186105b9888d6d6e5e6a38d51e585bac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "49db0dd90a12eed7137888391290cc9490642694b4305a6156e11481c5350045"

  strings:
    $s1 = "function _QUf8(s) {var _HYh0 = new Date();_HYh0.setUTCFullYear(\"2003\");if (_HYh0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _QUf8(s) {var _HYh0 = new Date();_HYh0.setUTCFullYear(\"2003\");if (_HYh0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ji1(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}