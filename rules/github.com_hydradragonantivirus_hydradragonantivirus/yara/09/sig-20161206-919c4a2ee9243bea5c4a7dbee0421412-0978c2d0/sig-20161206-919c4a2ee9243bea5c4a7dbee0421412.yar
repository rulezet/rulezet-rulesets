rule sig_20161206_919c4a2ee9243bea5c4a7dbee0421412 {
  meta:
    description = "datamaliciousorder - file 20161206_919c4a2ee9243bea5c4a7dbee0421412.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7d2ebc27b339520f8b6d510b870595fd9aa03007093a24714f4d897e444009d4"

  strings:
    $s1 = "function _Lt8(s) {var _Ik3 = new Date();_Ik3.setUTCFullYear(\"2003\");if (_Ik3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Lt8(s) {var _Ik3 = new Date();_Ik3.setUTCFullYear(\"2003\");if (_Ik3.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _VQf9(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}