rule Virus_Hijack_Gen_Trojan_ShellObject_m0Z_aKzulAn_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m0Z@aKzulAn_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ab75633c7794000c7a56a6f8f73f65821f48b64af231fbd26605aafd4f7440f"

  strings:
    $s1 = "Baht&+" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}