rule sig_20161205_f94ce848d526c9042e3f749f2b50bf12 {
  meta:
    description = "datamaliciousorder - file 20161205_f94ce848d526c9042e3f749f2b50bf12.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b1a07564ca8719466a8cef76f038cd33557ae829d86e321dabf384f7b8ba88a"

  strings:
    $s1 = "function _Nl1(s) {var _SNr7 = new Date();_SNr7.setUTCFullYear(\"2003\");if (_SNr7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s2 = "function _Nl1(s) {var _SNr7 = new Date();_SNr7.setUTCFullYear(\"2003\");if (_SNr7.getUTCFullYear().toString(10) == \"2003\") ret" ascii
    $s3 = "function _FKy6(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}