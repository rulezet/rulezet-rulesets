rule sig_20160824_e7643be6ccea4e31b2dff3c2ddba71da {
  meta:
    description = "datamaliciousorder - file 20160824_e7643be6ccea4e31b2dff3c2ddba71da.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b934dcce8f988974582e40f58aa8ef961ffa8f8c360c77e4c8d561a18c30dc77"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}