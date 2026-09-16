rule Virus_Hijack_GenPack_Backdoor_Hangup_B_114 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_114.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3aadc63c1a38ba55dd08ab9185ed0685609cf5709bd3a4cefecfcc1fdf88357f"

  strings:
    $s1 = "Lcreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}