rule sig_20161205_616a78dd056725718472016771c80952 {
  meta:
    description = "datamaliciousorder - file 20161205_616a78dd056725718472016771c80952.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "92ac72d5c9cd37398a181a79507f4bb468c7894430a7c256713fb488fd53f657"

  strings:
    $s1 = "function _FHq3(s) {var _Yp6 = new Date();_Yp6.setUTCFullYear(\"2003\");if (_Yp6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s2 = "function _FHq3(s) {var _Yp6 = new Date();_Yp6.setUTCFullYear(\"2003\");if (_Yp6.getUTCFullYear().toString(10) == \"2003\") retur" ascii
    $s3 = "function _TAv2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}