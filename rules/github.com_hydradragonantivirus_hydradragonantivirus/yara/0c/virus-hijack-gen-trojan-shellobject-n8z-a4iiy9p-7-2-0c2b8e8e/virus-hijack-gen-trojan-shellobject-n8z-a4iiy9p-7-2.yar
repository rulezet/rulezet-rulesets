rule Virus_Hijack_Gen_Trojan_ShellObject_n8Z_a4IIY9p_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.n8Z@a4IIY9p_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58ded6cf63661e64f29bda208155a3c155321da56a1cc5545e247e3855569f52"

  strings:
    $s1 = "B/%Sang" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}