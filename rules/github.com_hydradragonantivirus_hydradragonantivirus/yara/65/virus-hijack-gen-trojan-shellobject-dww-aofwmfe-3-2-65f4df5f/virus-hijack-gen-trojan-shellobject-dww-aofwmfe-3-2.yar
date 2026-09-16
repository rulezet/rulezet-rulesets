rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_3_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_3_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60a354697be42eef6a6d59ea907bdcfd4c5cd19784b333efd38078e7be5d450c"

  strings:
    $s1 = "pOnG'J" fullword ascii
    $s2 = "haRk({" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}