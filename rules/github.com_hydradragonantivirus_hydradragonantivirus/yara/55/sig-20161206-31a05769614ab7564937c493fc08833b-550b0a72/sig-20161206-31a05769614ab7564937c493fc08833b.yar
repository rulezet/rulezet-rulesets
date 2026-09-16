rule sig_20161206_31a05769614ab7564937c493fc08833b {
  meta:
    description = "datamaliciousorder - file 20161206_31a05769614ab7564937c493fc08833b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5bd91adec907b63bc6d595c874bc55a30c2a687437b7d07f7df73864d5a97905"

  strings:
    $s1 = "function _NYo9(s) {var _VHh2 = new Date();_VHh2.setUTCFullYear(\"2003\");if (_VHh2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _NYo9(s) {var _VHh2 = new Date();_VHh2.setUTCFullYear(\"2003\");if (_VHh2.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Xu8(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}