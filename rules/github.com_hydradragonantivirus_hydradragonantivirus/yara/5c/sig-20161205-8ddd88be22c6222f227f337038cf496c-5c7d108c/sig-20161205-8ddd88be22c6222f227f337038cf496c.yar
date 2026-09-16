rule sig_20161205_8ddd88be22c6222f227f337038cf496c {
  meta:
    description = "datamaliciousorder - file 20161205_8ddd88be22c6222f227f337038cf496c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "416ffe065abfa2e26826788382b887e1ea4ab9d65f9a157c0d9ac2f1a802fa5f"

  strings:
    $s1 = "function _HJq1(s) {var _BZo1 = new Date();_BZo1.setUTCFullYear(\"2003\");if (_BZo1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s2 = "function _HJq1(s) {var _BZo1 = new Date();_BZo1.setUTCFullYear(\"2003\");if (_BZo1.getUTCFullYear().toString(10) == \"2003\") re" ascii
    $s3 = "function _VNg9(s) {return s.split(\",\").join(\"\");};" fullword ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}