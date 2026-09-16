rule Virus_Hijack_GenPack_Backdoor_Hangup_B_216 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_216.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "13cb6576c5e8f480619993c2db3a98640bfb65366566ae2e3304010f20bc7c34"

  strings:
    $s1 = "#3Y*sAir" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}