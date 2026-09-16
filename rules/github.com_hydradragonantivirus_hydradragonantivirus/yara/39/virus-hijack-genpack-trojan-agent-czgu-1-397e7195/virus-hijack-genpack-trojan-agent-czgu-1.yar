rule Virus_Hijack_GenPack_Trojan_Agent_CZGU_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Trojan.Agent.CZGU_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a0ea4448263644184f3367358bfbcab85784a9849201b28d613fac45938c891"

  strings:
    $s1 = "gram FU" fullword ascii
    $s2 = "Module@1" fullword ascii
    $s3 = "CRITIC" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}