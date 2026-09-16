rule Virus_Hijack_Gen_Trojan_ShellObject_e4X_a8K8N6h_13_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e4X@a8K8N6h_13_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6391c46f73150fdd41392c502f33c4bd52a2ef4d8146a3dd9dc6b0770d944bd0"

  strings:
    $s1 = "*sTUm?" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}