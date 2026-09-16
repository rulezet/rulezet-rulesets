rule sig_20161205_ea44497ac06f5426ae6400f7dadba4e6 {
  meta:
    description = "datamaliciousorder - file 20161205_ea44497ac06f5426ae6400f7dadba4e6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0f8ca00bbe368378aa043edeb59ee28a199f00b34a318e9589d37d516878f2ee"

  strings:
    $s1 = "function _QId2(s) {var _Sg1 = new Date();_Sg1.setUTCFullYear(\"2003\");if (_Sg1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _QId2(s) {var _Sg1 = new Date();_Sg1.setUTCFullYear(\"2003\");if (_Sg1.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _GZy3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}