rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_amBwvTb_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@amBwvTb_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1104f89d2fb7002f87389627d46b6e93634906c8befa436560a7947c65b8c62a"

  strings:
    $s1 = "O*KiKi#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}