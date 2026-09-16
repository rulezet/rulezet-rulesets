rule sig_20161205_40c88ee1ec07126f29eb93811e927928 {
  meta:
    description = "datamaliciousorder - file 20161205_40c88ee1ec07126f29eb93811e927928.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90e457e2877a750317f07e6999b252eb705317083aebfc12d0cd79bc83b26ae3"

  strings:
    $s1 = "function _IWa3(s) {var _IUe3 = new Date();_IUe3.setUTCFullYear(\"2003\");if (_IUe3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _IWa3(s) {var _IUe3 = new Date();_IUe3.setUTCFullYear(\"2003\");if (_IUe3.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Nf1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}