rule Trojan_Danger_Trojan_GenericKD_67166905_299_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_299_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3981d47a16c2d1887d02e9cd51bfb9730e54645eb5b92222a6c027b8e1889528"

  strings:
    $s1 = "2. Notice of Dispute. In the event of a dispute, you or Microsoft must give the oth`" fullword ascii
    $s2 = "E!sPAk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}