rule sig_20161205_b011603e0d726b41e37827fa1182e3a0 {
  meta:
    description = "datamaliciousorder - file 20161205_b011603e0d726b41e37827fa1182e3a0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75ef3e7762af7d6c238ee9ea03dc93c7b90cf6182c31c9f02fca68b317b1cd90"

  strings:
    $s1 = "function _Kb6(s) {var _Zy2 = new Date();_Zy2.setUTCFullYear(\"2003\");if (_Zy2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s2 = "function _Kb6(s) {var _Zy2 = new Date();_Zy2.setUTCFullYear(\"2003\");if (_Zy2.getUTCFullYear().toString(10) == \"2003\") return" ascii
    $s3 = "function _Qw6(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}