rule Virus_Hijack_Gen_Trojan_ShellObject_dyX_amUgp3c_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyX@amUgp3c_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06d8efdf870c7e76d8ea4d6e7badb9e6544a1527162ec409370689f311cb6095"

  strings:
    $s1 = "Windows Audio Device Graph Isolation" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}