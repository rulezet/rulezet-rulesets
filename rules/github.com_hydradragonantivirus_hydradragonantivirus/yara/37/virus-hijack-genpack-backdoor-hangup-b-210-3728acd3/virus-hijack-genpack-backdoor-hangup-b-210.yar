rule Virus_Hijack_GenPack_Backdoor_Hangup_B_210 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_210.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f81991014104342e2a4ef864a07907be1cb354439d3de904583dad56c1a20c6"

  strings:
    $s1 = "+software manually by Internet or telephone. In either case, Internet and telephone service charges may" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}