rule sig_20161206_5bb57874c3acfd38fec635af8b773e8f {
  meta:
    description = "datamaliciousorder - file 20161206_5bb57874c3acfd38fec635af8b773e8f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc0a7bd0424c54b8e0b8e098c0c45bd2e61e0917fd80d8a2334f9f25bbc1e6c0"

  strings:
    $s1 = "function _Sq1(s) {var _KDf0 = new Date();_KDf0.setUTCFullYear(\"2003\");if (_KDf0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Sq1(s) {var _KDf0 = new Date();_KDf0.setUTCFullYear(\"2003\");if (_KDf0.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _YBl3(s) {return s[\"split\"](\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}