rule Trojan_Autorun_Gen_Trojan_Backdoor2_fmZbaKq9kbjb_5_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.fmZbaKq9kbjb_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "195fe7e3148e9eca10f9e5486d961a8dd12c363e4e8e9f8beb4487ea6e4cd7e0"

  strings:
    $s1 = "Rfunctionality of the programs. You have 30 days " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}