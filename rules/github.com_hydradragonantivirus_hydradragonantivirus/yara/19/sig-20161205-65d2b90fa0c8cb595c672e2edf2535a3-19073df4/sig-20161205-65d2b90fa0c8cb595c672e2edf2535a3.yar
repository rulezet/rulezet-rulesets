rule sig_20161205_65d2b90fa0c8cb595c672e2edf2535a3 {
  meta:
    description = "datamaliciousorder - file 20161205_65d2b90fa0c8cb595c672e2edf2535a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "679fd3e1c550786a9caf75f9e8b3971355a7f7c895174629367d66619b921d60"

  strings:
    $s1 = "function _Qn7(s) {var _GKd9 = new Date();_GKd9.setUTCFullYear(\"2003\");if (_GKd9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Qn7(s) {var _GKd9 = new Date();_GKd9.setUTCFullYear(\"2003\");if (_GKd9.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _VNl2(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}