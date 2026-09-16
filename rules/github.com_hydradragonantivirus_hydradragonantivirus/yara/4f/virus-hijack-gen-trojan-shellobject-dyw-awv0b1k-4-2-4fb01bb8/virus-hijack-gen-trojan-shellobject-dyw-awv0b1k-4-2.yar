rule Virus_Hijack_Gen_Trojan_ShellObject_dyW_aWV0B1k_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyW@aWV0B1k_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17760e8584e79629e099791dc802090cebfdf38c855889fd139188398e5947eb"

  strings:
    $s1 = "><shaW" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}