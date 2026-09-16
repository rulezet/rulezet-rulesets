rule Trojan_Autorun_Gen_Trojan_Backdoor2_MmZbaKq9kbjb_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.MmZbaKq9kbjb_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbf5d421f6b31634f90238460c4704cd5206a0cd94bb5b8df00dcee98b3823d6"

  strings:
    $s1 = "functionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}