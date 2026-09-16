rule sig_20160824_ba04c3674808378106da9a7194ff0e2a {
  meta:
    description = "datamaliciousorder - file 20160824_ba04c3674808378106da9a7194ff0e2a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e602bd6cac017df4d1c127fce1468c7671e179c814c6723de4feb87473bff4c4"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}