rule Virus_Hijack_GenPack_Backdoor_Hangup_B_290 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_290.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53df5b731667f8ebb19d93c9b3ad36c0bf28b9452319485b66ea307d4ecc68eb"

  strings:
    $s1 = "lyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}