rule Virus_Hijack_Gen_Trojan_ShellObject_g8X_ait5o7p_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8X@ait5o7p_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "98452e8a0535a9065deeee69dacb1cfe0e95e521a195023eb6b07dac11ed5bb4"

  strings:
    $s1 = "Daytimes" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}