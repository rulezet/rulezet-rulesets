rule Virus_Hijack_Gen_Trojan_ShellObject_k8Z_au4JtZd_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k8Z@au4JtZd_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c8b83cb730ac16916ef521f284c6654101479dc5d5d15593a2fde74effe735bf"

  strings:
    $s1 = "H'6,sWim" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}