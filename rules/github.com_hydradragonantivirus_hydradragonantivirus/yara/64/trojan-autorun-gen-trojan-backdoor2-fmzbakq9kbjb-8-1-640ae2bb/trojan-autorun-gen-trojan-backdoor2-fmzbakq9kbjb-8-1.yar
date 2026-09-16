rule Trojan_Autorun_Gen_Trojan_Backdoor2_FmZbaKq9kbjb_8_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.FmZbaKq9kbjb_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "72604db35b596598f30c12b99a79c7c737df4aa0aadfd6548ebe8944d1172f3c"

  strings:
    $s1 = "u4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}