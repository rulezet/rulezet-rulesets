rule Virus_Hijack_Backdoor_Hangup_B_151 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_151.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0405af4386a6e1c56a66641324fafa4cb05546f7104b47793f46d9da7619a6a4"

  strings:
    $s1 = "X@your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}