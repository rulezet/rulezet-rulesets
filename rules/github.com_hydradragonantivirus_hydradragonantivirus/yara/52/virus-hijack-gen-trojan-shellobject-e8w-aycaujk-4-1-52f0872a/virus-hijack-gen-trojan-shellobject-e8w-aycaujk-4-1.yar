rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c79a2e1280f20297fc93a4c0c8fd3174c2908bfe02741f7a101162636242eaf0"

  strings:
    $s1 = "\"Powered by SmartAssembly 6.8.0.121" fullword ascii
    $s2 = "agEe#}]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}