rule Virus_Hijack_GenPack_Backdoor_Hangup_B_55_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_55_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "837253d209389494f36b891fea3b0ad947c365d9ed1fdcc090720693a61dd070"

  strings:
    $s1 = "Arrays::ARR<unsigned char>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}