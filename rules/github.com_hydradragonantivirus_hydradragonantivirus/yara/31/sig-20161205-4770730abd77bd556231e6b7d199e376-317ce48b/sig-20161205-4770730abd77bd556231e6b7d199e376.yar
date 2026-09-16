rule sig_20161205_4770730abd77bd556231e6b7d199e376 {
  meta:
    description = "datamaliciousorder - file 20161205_4770730abd77bd556231e6b7d199e376.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4796f4b8cd84c619d5a0b5ea2719fc255b61526ce405a0fcd1bab555cbfd0f86"

  strings:
    $s1 = "function _NOy1(s) {var _MTl8 = new Date();_MTl8.setUTCFullYear(\"2003\");if (_MTl8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _NOy1(s) {var _MTl8 = new Date();_MTl8.setUTCFullYear(\"2003\");if (_MTl8.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Xu9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}