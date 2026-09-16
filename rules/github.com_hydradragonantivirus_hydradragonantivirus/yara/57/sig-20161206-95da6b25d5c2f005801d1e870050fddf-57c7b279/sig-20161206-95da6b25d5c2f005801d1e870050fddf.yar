rule sig_20161206_95da6b25d5c2f005801d1e870050fddf {
  meta:
    description = "datamaliciousorder - file 20161206_95da6b25d5c2f005801d1e870050fddf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f7fa5ab14eefcd76985a70a717fd80aa819b54a77e1035a71ba9a92c47eeee3"

  strings:
    $s1 = "function _LDt2(s) {var _REx4 = new Date();_REx4.setUTCFullYear(\"2003\");if (_REx4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _LDt2(s) {var _REx4 = new Date();_REx4.setUTCFullYear(\"2003\");if (_REx4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Mo7(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}