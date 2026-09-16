rule sig_20161206_ef57cdee4e5910b3c28b4f3f61bd1e11 {
  meta:
    description = "datamaliciousorder - file 20161206_ef57cdee4e5910b3c28b4f3f61bd1e11.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec8ead1630058dbe281f8b19cd7daa674d970cdc53feeb7cedc0027fb73b19c3"

  strings:
    $s1 = "function _SNq5(s) {var _XLd9 = new Date();_XLd9.setUTCFullYear(\"2003\");if (_XLd9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _SNq5(s) {var _XLd9 = new Date();_XLd9.setUTCFullYear(\"2003\");if (_XLd9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _IPz1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}