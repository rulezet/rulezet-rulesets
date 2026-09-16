rule sig_20161205_f91fbe9833c0b107f25e3fa8239046fe {
  meta:
    description = "datamaliciousorder - file 20161205_f91fbe9833c0b107f25e3fa8239046fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "56658193318fa464827a3f655b397decdc72663b44f4d872a169040b83ea79ad"

  strings:
    $s1 = "function _AXf7(s) {var _He3 = new Date();_He3.setUTCFullYear(\"2003\");if (_He3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _AXf7(s) {var _He3 = new Date();_He3.setUTCFullYear(\"2003\");if (_He3.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _Zx1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}