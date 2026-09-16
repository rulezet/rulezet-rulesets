rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_au4JtZd_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@au4JtZd_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1eb7004c37b0bb56ca06b7790ff981c6f70e132a91c37e645acd2f1512d9e415"

  strings:
    $s1 = "redO( " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}