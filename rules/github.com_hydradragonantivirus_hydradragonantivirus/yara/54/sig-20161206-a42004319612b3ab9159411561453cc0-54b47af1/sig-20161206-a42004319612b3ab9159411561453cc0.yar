rule sig_20161206_a42004319612b3ab9159411561453cc0 {
  meta:
    description = "datamaliciousorder - file 20161206_a42004319612b3ab9159411561453cc0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "869479a9b44efee7da5c8271daccaea4f75f216e394030a63f29951307e13ca2"

  strings:
    $s1 = "function _Xi3(s) {var _Go5 = new Date();_Go5.setUTCFullYear(\"2003\");if (_Go5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Xi3(s) {var _Go5 = new Date();_Go5.setUTCFullYear(\"2003\");if (_Go5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Eo7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}