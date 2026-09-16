rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKoUq3b_25_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKoUq3b_25_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "607e339005e2ec43fa1f8db7f90cec8f97c54031e1672cd76c38ccb1125d4fdb"

  strings:
    $s1 = "open type waveaudio" fullword ascii
    $s2 = "MS Corporation" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}