rule Virus_Hijack_Gen_Trojan_ShellObject_h8Y_a0a9m9p {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.h8Y@a0a9m9p.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b161afedd5d4ce89b4d1d85f8110202d69a096e0161b4361cd5fa78f62f6a93"

  strings:
    $s1 = "xSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}