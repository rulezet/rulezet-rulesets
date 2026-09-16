rule sig_20161205_03476173ef9fdec7e5270dc7d87933f0 {
  meta:
    description = "datamaliciousorder - file 20161205_03476173ef9fdec7e5270dc7d87933f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b89fdbbe855d6491565249508472f2eff89733cf370f49725228a13ac2e69d61"

  strings:
    $s1 = "function _Kz3(s) {var _Jc5 = new Date();_Jc5.setUTCFullYear(\"2003\");if (_Jc5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Kz3(s) {var _Jc5 = new Date();_Jc5.setUTCFullYear(\"2003\");if (_Jc5.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Kf6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}