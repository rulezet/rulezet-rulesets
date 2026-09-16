rule sig_20161206_0432534766255f7d67d64e46f0968429 {
  meta:
    description = "datamaliciousorder - file 20161206_0432534766255f7d67d64e46f0968429.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87b5d8c3cb38af39a447c9af575149ec61a0318e90bec4525e2f3e13df1c292d"

  strings:
    $s1 = "function _QKt7(s) {var _We7 = new Date();_We7.setUTCFullYear(\"2003\");if (_We7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _QKt7(s) {var _We7 = new Date();_We7.setUTCFullYear(\"2003\");if (_We7.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _RJw9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}