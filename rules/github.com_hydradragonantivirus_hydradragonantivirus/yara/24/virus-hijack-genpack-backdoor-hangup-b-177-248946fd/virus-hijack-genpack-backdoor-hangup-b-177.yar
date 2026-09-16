rule Virus_Hijack_GenPack_Backdoor_Hangup_B_177 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_177.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2039ccc692c96b99efa6651a54d80eafcd4a2c659791eb25c344a04e37d93793"

  strings:
    $s1 = "#Professional User " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}