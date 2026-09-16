rule sig_20161205_b89e9e7252523731481d1ecc2251623b {
  meta:
    description = "datamaliciousorder - file 20161205_b89e9e7252523731481d1ecc2251623b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8edbd02d16e3c381aa5ccad0559f29f97fb4a76ba2d647dce6760feb2a49cd2f"

  strings:
    $s1 = "function _HVw5(s) {var _MGi6 = new Date();_MGi6.setUTCFullYear(\"2003\");if (_MGi6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _HVw5(s) {var _MGi6 = new Date();_MGi6.setUTCFullYear(\"2003\");if (_MGi6.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _Ed4(s) {return (\"asdf\", s.split(\",\").join(\"\"));};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}