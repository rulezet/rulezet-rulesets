rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_46 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_46.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "301976c1b1fcd17bf3cdca233ade78eb59005741619d7bac4f5014181a6a0259"

  strings:
    $s1 = "PurR)pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}