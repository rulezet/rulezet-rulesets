rule Virus_Hijack_Dropped_Backdoor_Padodor_BJ_780_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Dropped.Backdoor.Padodor.BJ_780_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a562457ec46daa26519c7e3dddb77a54474d0793efb8d745d24e76bbe3b9463"

  strings:
    $s1 = "leucoplakia" fullword wide
    $s2 = "8+6<FeEd" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}