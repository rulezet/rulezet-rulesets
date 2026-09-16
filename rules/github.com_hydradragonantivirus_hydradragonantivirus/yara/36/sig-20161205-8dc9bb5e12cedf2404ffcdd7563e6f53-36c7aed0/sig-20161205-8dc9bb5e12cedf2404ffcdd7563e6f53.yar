rule sig_20161205_8dc9bb5e12cedf2404ffcdd7563e6f53 {
  meta:
    description = "datamaliciousorder - file 20161205_8dc9bb5e12cedf2404ffcdd7563e6f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "392b2f2a7d880d070dd5d5ce012186b60c7e64d3186394dca5b99aec64b3ce1c"

  strings:
    $s1 = "function _Gc4(s) {var _VEc2 = new Date();_VEc2.setUTCFullYear(\"2003\");if (_VEc2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Gc4(s) {var _VEc2 = new Date();_VEc2.setUTCFullYear(\"2003\");if (_VEc2.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _FTx3(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}