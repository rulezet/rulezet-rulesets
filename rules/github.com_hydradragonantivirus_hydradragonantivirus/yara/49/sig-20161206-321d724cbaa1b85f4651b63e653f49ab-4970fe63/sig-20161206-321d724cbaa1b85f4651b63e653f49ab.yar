rule sig_20161206_321d724cbaa1b85f4651b63e653f49ab {
  meta:
    description = "datamaliciousorder - file 20161206_321d724cbaa1b85f4651b63e653f49ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2b9d0da6083d07f2e9c50ef0f89a14e43d7e9981d07105fdc9477e7a72c235f"

  strings:
    $s1 = "function _XNw7(s) {var _ZAd9 = new Date();_ZAd9.setUTCFullYear(\"2003\");if (_ZAd9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _XNw7(s) {var _ZAd9 = new Date();_ZAd9.setUTCFullYear(\"2003\");if (_ZAd9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Oc0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}