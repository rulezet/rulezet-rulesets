rule Virus_Autorun_Gen_Variant_Genie_10_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Gen.Variant.Genie.10_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6271da4cdd8520e32d4d3eadb2a8a06c32e11c68c5fe03e319b6846f84fbae53"

  strings:
    $s1 = "Disk Cleanup.lnk.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}