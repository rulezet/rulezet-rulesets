rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_61 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_61.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d90f495797c4fd0f99c44f089dd7bec42bf5c7166236fb28af2f48906be72cb0"

  strings:
    $s1 = "*sTUm?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}