rule Virus_Hijack_GenPack_Backdoor_Hangup_B_142 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_142.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6ca740e385a2b8c8ea52e7364577ff5067149c4ccce9f7950840e7f6f404107c"

  strings:
    $s1 = "Lyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}