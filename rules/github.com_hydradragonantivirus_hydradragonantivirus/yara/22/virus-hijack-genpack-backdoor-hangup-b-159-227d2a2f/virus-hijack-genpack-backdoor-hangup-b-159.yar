rule Virus_Hijack_GenPack_Backdoor_Hangup_B_159 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_159.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "59123496e6bd337a0ad2c19d7b8dee0ca4a4bb2bf3081a1ff81ca442bd550694"

  strings:
    $s1 = "GTrade Compliance web site which can be accessed at http://oracle.com/contracts. You agree that no data, information," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}