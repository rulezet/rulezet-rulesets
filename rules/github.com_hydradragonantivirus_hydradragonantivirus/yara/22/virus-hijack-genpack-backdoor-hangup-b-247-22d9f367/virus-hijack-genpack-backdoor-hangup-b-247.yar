rule Virus_Hijack_GenPack_Backdoor_Hangup_B_247 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_247.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2821f1d1b0638e9247ead1d42eeb388aa094f09a21bb018efd8fdc0cd4a7d8ed"

  strings:
    $s1 = "\"and hardware systems to the applications programs and (c) building extensions to applications programs. You shall not" fullword ascii
    $s2 = "the same degree of care to safeguard the confidentiality of the TRMs as you exercise to safeguard the confidenti`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}