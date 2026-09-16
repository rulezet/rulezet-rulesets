rule sig_20161205_c4b165e4a6006f3e5497f7a3c2c13712 {
  meta:
    description = "datamaliciousorder - file 20161205_c4b165e4a6006f3e5497f7a3c2c13712.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f46a4e9abffc66567471d0259b4ebfc78153d08f5c2bacd514648c8d19467d84"

  strings:
    $s1 = "function _OTc1(s) {var _Fe2 = new Date();_Fe2.setUTCFullYear(\"2003\");if (_Fe2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _OTc1(s) {var _Fe2 = new Date();_Fe2.setUTCFullYear(\"2003\");if (_Fe2.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _GWz5(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}