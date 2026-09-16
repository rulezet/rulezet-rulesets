rule Virus_Hijack_GenPack_Backdoor_Hangup_B_380 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_380.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4b92e1a66bb93fd5ba60601ddcdcb4c0c82ee66b6680a41e59eef04ce97abb66"

  strings:
    $s1 = "P=rRFk:PG\"polL" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}