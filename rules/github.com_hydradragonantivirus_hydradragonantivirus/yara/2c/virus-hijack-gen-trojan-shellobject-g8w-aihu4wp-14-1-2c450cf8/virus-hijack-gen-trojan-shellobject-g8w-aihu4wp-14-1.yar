rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aiHu4Wp_14_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aiHu4Wp_14_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "29f4a7219a671bac2337402c9c5fd4cf1789ac818c321754b8824b486ffb717d"

  strings:
    $s1 = "File is invalid." fullword wide
    $s2 = "Inter!op" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}