rule Virus_Hijack_Gen_Trojan_ShellObject_BuZ_amBwvTb_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.BuZ@amBwvTb_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d45f799a202bad0c45997c2be5f4ae2b71620719a4977ca4f3179495b532359f"

  strings:
    $s1 = "LoWN<@hC" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}