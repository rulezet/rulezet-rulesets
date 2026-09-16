rule Virus_Hijack_Gen_Trojan_ShellObject_dCW_aGhujNi_54_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dCW@aGhujNi_54_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0276da2eea0a036a84e403fd56b16a667c4b0f418325f7dccc57f8f3ba63ecf"

  strings:
    $s1 = "><shaW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}