rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_29_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_29_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f05dbf4919a8fc42eb0be6f0e8ea33489047e1527de320bc01b79058f7e3483f"

  strings:
    $s1 = "*sTUm?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}