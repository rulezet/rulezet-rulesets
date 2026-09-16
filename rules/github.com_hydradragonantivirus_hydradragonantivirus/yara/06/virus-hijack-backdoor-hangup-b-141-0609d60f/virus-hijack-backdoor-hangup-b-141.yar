rule Virus_Hijack_Backdoor_Hangup_B_141 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_141.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4fd51e5c64d1a932e3956977fd387a08153d618ed286c4897193e384227aa6de"

  strings:
    $s1 = "SA. Agreement Definitions" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}