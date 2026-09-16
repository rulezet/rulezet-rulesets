rule sig_20161206_0b77c1d00d433d2bfebe319cd2067131 {
  meta:
    description = "datamaliciousorder - file 20161206_0b77c1d00d433d2bfebe319cd2067131.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6c54dc81224e68f12e6a66b00018e16133b6375636d8eb60db9b0a7fd5cdfd4"

  strings:
    $s1 = "function _IFj7(s) {var _CCx6 = new Date();_CCx6.setUTCFullYear(\"2003\");if (_CCx6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _IFj7(s) {var _CCx6 = new Date();_CCx6.setUTCFullYear(\"2003\");if (_CCx6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _FMh6(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}