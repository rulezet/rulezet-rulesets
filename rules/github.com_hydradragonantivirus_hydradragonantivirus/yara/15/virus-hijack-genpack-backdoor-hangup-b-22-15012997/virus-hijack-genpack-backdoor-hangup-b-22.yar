rule Virus_Hijack_GenPack_Backdoor_Hangup_B_22 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_22.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "600f996e52d082938060ddf4cb83f1f20ff6016d1297b065e071951b4a0f8d46"

  strings:
    $s1 = ",your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}