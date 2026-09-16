rule sig_20161205_d0a20f3ad3b7a2c399a9f9c8245dd76f {
  meta:
    description = "datamaliciousorder - file 20161205_d0a20f3ad3b7a2c399a9f9c8245dd76f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a92fabe3ad5c2e51fe204e977772c935e3caeab6eb1c779a9258c7758eaff0c6"

  strings:
    $s1 = "function _VSp9(s) {var _SAv4 = new Date();_SAv4.setUTCFullYear(\"2003\");if (_SAv4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _VSp9(s) {var _SAv4 = new Date();_SAv4.setUTCFullYear(\"2003\");if (_SAv4.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _OYc1(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}