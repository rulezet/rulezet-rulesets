rule Trojan_Danger_Trojan_GenericKD_72304918_41_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_41_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e11dadd3b1a8abdf753a10c490239ca8b6511384e58dbdf9499252d1fea57945"

  strings:
    $s1 = "You may not assign this agreement or give or transfer the programs and/or any services or an interest in them " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}