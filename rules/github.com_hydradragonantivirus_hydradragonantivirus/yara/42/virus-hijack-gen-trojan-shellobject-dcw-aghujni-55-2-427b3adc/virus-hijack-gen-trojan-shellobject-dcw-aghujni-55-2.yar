rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_55_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_55_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "502c37c9e919e2e9072a91e6251a55c891b591a12ca3d14aa9a87039072fca10"

  strings:
    $s1 = "rEcCy?_" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}