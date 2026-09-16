rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_41_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_41_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f7f4c319b1b67c71d8b0042b6aabc2f2a601f5f4a3af7ab125704c0c13cc08a"

  strings:
    $s1 = "*sTUm?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}