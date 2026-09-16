rule sig_20161205_6c47a1b90fdb7ef614457cf031d0fd61 {
  meta:
    description = "datamaliciousorder - file 20161205_6c47a1b90fdb7ef614457cf031d0fd61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8e86ae1daafa4c551bec5b3bc1215a1f6cb76666ef4dd9b0aa10bf91bd65898"

  strings:
    $s1 = "function _Gt6(s) {var _HXz3 = new Date();_HXz3.setUTCFullYear(\"2003\");if (_HXz3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Gt6(s) {var _HXz3 = new Date();_HXz3.setUTCFullYear(\"2003\");if (_HXz3.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _PFu1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}