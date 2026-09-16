rule sig_20161206_b4b8f8b5d9412837b7342b2724b2317a {
  meta:
    description = "datamaliciousorder - file 20161206_b4b8f8b5d9412837b7342b2724b2317a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3fd0cb945904a0557bad44268db92e3ce66939776c9fce07711250cc930a6f61"

  strings:
    $s1 = "function _WTe2(s) {var _QKk0 = new Date();_QKk0.setUTCFullYear(\"2003\");if (_QKk0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _WTe2(s) {var _QKk0 = new Date();_QKk0.setUTCFullYear(\"2003\");if (_QKk0.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Xo5(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}