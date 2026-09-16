rule sig_20161206_1b553689654c5a188ecf91954822ebed {
  meta:
    description = "datamaliciousorder - file 20161206_1b553689654c5a188ecf91954822ebed.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bad0a69117c43e50787ea7ae660bf15216d670f46071f8ced861fc4d67f5507"

  strings:
    $s1 = "function _We6(s) {var _AFx6 = new Date();_AFx6.setUTCFullYear(\"2003\");if (_AFx6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _We6(s) {var _AFx6 = new Date();_AFx6.setUTCFullYear(\"2003\");if (_AFx6.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Hr1(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}