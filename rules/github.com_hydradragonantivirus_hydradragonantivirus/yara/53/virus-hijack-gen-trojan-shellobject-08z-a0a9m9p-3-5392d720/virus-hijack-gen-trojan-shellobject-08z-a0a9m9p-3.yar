rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_a0a9m9p_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@a0a9m9p_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "87dc43d45c2d3914a049b9e638096aac66e1b7224aa6702eb43b0c89258fedfc"

  strings:
    $s1 = "[2Software Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}