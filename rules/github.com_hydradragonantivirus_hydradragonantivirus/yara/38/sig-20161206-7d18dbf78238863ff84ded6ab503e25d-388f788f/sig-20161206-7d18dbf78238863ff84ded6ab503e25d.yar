rule sig_20161206_7d18dbf78238863ff84ded6ab503e25d {
  meta:
    description = "datamaliciousorder - file 20161206_7d18dbf78238863ff84ded6ab503e25d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c57c1aa592a2fb0b9c8237b6a84d7b99a2d48fc4f671a45be4e011fd9cb679b2"

  strings:
    $s1 = "function _MIj8(s) {var _JPc9 = new Date();_JPc9.setUTCFullYear(\"2003\");if (_JPc9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _MIj8(s) {var _JPc9 = new Date();_JPc9.setUTCFullYear(\"2003\");if (_JPc9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Om7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}