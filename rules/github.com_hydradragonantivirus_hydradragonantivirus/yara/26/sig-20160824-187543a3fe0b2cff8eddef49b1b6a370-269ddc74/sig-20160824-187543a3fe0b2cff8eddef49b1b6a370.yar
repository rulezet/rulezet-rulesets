rule sig_20160824_187543a3fe0b2cff8eddef49b1b6a370 {
  meta:
    description = "datamaliciousorder - file 20160824_187543a3fe0b2cff8eddef49b1b6a370.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "710b5e6cba6d72fef1ff1932ec6ebe0f709fdfc1c38c7f8846875d7b495be03f"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}