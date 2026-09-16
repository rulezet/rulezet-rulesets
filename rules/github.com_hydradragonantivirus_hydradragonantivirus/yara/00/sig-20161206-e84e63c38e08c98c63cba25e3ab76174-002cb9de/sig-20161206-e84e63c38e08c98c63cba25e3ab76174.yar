rule sig_20161206_e84e63c38e08c98c63cba25e3ab76174 {
  meta:
    description = "datamaliciousorder - file 20161206_e84e63c38e08c98c63cba25e3ab76174.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d91c3a803ec9c4948513f83bbf7246a0d141b932f93efb7cf5cda2f68ae7ee37"

  strings:
    $s1 = "function _MBv7(s) {var _EOa9 = new Date();_EOa9.setUTCFullYear(\"2003\");if (_EOa9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _MBv7(s) {var _EOa9 = new Date();_EOa9.setUTCFullYear(\"2003\");if (_EOa9.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _VKh0(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}