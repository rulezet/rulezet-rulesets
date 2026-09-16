rule sig_20161205_01af096dcd47fc103bbe512ed149ce59 {
  meta:
    description = "datamaliciousorder - file 20161205_01af096dcd47fc103bbe512ed149ce59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "66fdf80fa8408f89d2e0d2c15e1e9a634bd064b218aa143e849c9e68eafa5096"

  strings:
    $s1 = "function _SBp9(s) {var _CAi5 = new Date();_CAi5.setUTCFullYear(\"2003\");if (_CAi5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _SBp9(s) {var _CAi5 = new Date();_CAi5.setUTCFullYear(\"2003\");if (_CAi5.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Tv7(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}