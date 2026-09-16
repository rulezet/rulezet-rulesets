rule sig_20161206_b1e6fec4c462ab72e1a80b2103a9c790 {
  meta:
    description = "datamaliciousorder - file 20161206_b1e6fec4c462ab72e1a80b2103a9c790.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "771bac8ca50b170db47be5baea2617d890c5356245a0e8dc6a1ce418dbaeaaa4"

  strings:
    $s1 = "function _XHo4(s) {var _YPd0 = new Date();_YPd0.setUTCFullYear(\"2003\");if (_YPd0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _XHo4(s) {var _YPd0 = new Date();_YPd0.setUTCFullYear(\"2003\");if (_YPd0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Da3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}