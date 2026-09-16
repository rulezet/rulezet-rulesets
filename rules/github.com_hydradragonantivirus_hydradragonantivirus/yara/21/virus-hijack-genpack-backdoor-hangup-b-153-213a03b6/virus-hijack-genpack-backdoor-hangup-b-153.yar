rule Virus_Hijack_GenPack_Backdoor_Hangup_B_153 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_153.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db7602665bbfb4408e4d1f8c037c69aec76f12999c493f0c3953b87d24ae735e"

  strings:
    $s1 = "l>create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}