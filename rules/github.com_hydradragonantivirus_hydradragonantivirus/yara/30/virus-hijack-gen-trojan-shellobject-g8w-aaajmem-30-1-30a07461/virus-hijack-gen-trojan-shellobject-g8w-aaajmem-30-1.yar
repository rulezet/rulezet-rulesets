rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aaajMem_30_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aaajMem_30_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c73ededbd325db1e55674a08ebb66c522e44af25e4205bf50fb2c4ef2ea576d5"

  strings:
    $s1 = "stUT]FC" fullword ascii
    $s2 = "F]>PLop" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}