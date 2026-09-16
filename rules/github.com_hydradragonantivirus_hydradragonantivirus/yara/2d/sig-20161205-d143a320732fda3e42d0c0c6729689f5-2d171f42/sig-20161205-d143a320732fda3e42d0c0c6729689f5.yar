rule sig_20161205_d143a320732fda3e42d0c0c6729689f5 {
  meta:
    description = "datamaliciousorder - file 20161205_d143a320732fda3e42d0c0c6729689f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5018095d54712be85f1a4991d6bb90e0346db097757b5697ed319bc319b9ee2"

  strings:
    $s1 = "function _Of1(s) {var _MPg5 = new Date();_MPg5.setUTCFullYear(\"2003\");if (_MPg5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Of1(s) {var _MPg5 = new Date();_MPg5.setUTCFullYear(\"2003\");if (_MPg5.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _GXn5(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}