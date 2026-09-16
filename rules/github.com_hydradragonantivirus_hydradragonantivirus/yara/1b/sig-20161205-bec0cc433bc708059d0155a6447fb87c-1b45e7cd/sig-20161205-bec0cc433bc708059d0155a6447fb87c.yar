rule sig_20161205_bec0cc433bc708059d0155a6447fb87c {
  meta:
    description = "datamaliciousorder - file 20161205_bec0cc433bc708059d0155a6447fb87c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "219ad41cb99589901edce5369caf08d51b6056ce0d619bc4da73da2961cda649"

  strings:
    $s1 = "function _Bc8(s) {var _Hd6 = new Date();_Hd6.setUTCFullYear(\"2003\");if (_Hd6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Bc8(s) {var _Hd6 = new Date();_Hd6.setUTCFullYear(\"2003\");if (_Hd6.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _WYj5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}