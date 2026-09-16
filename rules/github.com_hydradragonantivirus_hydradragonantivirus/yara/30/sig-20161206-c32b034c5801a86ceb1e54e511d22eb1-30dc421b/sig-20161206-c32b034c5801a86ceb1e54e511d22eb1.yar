rule sig_20161206_c32b034c5801a86ceb1e54e511d22eb1 {
  meta:
    description = "datamaliciousorder - file 20161206_c32b034c5801a86ceb1e54e511d22eb1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54e138a42493abce3bc737ca189e142be41717f0fe68b08bdbea17c6cb4cfb21"

  strings:
    $s1 = "function _Oh1(s) {var _IFf2 = new Date();_IFf2.setUTCFullYear(\"2003\");if (_IFf2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Oh1(s) {var _IFf2 = new Date();_IFf2.setUTCFullYear(\"2003\");if (_IFf2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _Di8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}