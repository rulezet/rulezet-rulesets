rule sig_20161205_ca43f6540c7e8e18befa28782a0c2d85 {
  meta:
    description = "datamaliciousorder - file 20161205_ca43f6540c7e8e18befa28782a0c2d85.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a77aef3d63f56f3412b6995b436fa1a60855b7815537754c3c7b6d617d382f66"

  strings:
    $s1 = "function _NDe5(s) {var _Wd0 = new Date();_Wd0.setUTCFullYear(\"2003\");if (_Wd0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _NDe5(s) {var _Wd0 = new Date();_Wd0.setUTCFullYear(\"2003\");if (_Wd0.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Ok9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}