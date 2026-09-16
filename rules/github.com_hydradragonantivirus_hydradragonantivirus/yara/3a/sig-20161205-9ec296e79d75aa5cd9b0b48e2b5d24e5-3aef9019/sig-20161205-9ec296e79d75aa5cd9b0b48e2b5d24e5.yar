rule sig_20161205_9ec296e79d75aa5cd9b0b48e2b5d24e5 {
  meta:
    description = "datamaliciousorder - file 20161205_9ec296e79d75aa5cd9b0b48e2b5d24e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cc97ce2b7e7a41bea838bf6a7ea16a6f1f7a679a7922d9aab650cac5056b8fab"

  strings:
    $s1 = "function _JHg1(s) {var _UMw6 = new Date();_UMw6.setUTCFullYear(\"2003\");if (_UMw6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _JHg1(s) {var _UMw6 = new Date();_UMw6.setUTCFullYear(\"2003\");if (_UMw6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Si4(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}