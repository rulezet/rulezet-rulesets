rule sig_20161205_93410888734b394c55da9b234f209656 {
  meta:
    description = "datamaliciousorder - file 20161205_93410888734b394c55da9b234f209656.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b0532fb47fc2dacfc8522e3df304e18983bb143c248be2f8341f935fca19e411"

  strings:
    $s1 = "function _UKu5(s) {var _Dw3 = new Date();_Dw3.setUTCFullYear(\"2003\");if (_Dw3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _UKu5(s) {var _Dw3 = new Date();_Dw3.setUTCFullYear(\"2003\");if (_Dw3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _GZf7(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}