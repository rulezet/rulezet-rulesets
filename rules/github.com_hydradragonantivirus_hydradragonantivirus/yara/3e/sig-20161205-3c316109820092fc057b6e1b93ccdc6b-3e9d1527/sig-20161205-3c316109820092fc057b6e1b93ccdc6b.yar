rule sig_20161205_3c316109820092fc057b6e1b93ccdc6b {
  meta:
    description = "datamaliciousorder - file 20161205_3c316109820092fc057b6e1b93ccdc6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb1b94b800b4f69d45404272d6d92da81ccfb9918252c12a5b56d911140557f2"

  strings:
    $s1 = "function _TDp4(s) {var _Rb3 = new Date();_Rb3.setUTCFullYear(\"2003\");if (_Rb3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _TDp4(s) {var _Rb3 = new Date();_Rb3.setUTCFullYear(\"2003\");if (_Rb3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Cb9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}