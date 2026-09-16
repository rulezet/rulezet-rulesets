rule Virus_Hijack_GenPack_Backdoor_Hangup_B_218 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_218.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44b9540b6fbdf583eed9b11120a589f752ae8552157eb22cd4835ac44362823b"

  strings:
    $s1 = "land hardware systems to the applications programs and (c) building extensions to applications programs. You shall not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}