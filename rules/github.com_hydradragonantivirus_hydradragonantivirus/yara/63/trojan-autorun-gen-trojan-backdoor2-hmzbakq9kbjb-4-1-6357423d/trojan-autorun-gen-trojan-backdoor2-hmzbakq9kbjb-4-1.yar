rule Trojan_Autorun_Gen_Trojan_Backdoor2_HmZbaKq9kbjb_4_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Gen.Trojan.Backdoor2.HmZbaKq9kbjb_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9afa4e5844f069e5510c37ff93972913bc3f5246d7409d903d02c8546810d1e3"

  strings:
    $s1 = "L4. Language Packs and Proofing Tools. If you acq" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}