rule Virus_Hijack_Gen_Trojan_ShellObject_f0W_a0DbbBi_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f0W@a0DbbBi_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef83ba6544e2aa1b6a38171b45706b83633efafd0f33225b457704927812a723"

  strings:
    $s1 = "soft Visual " fullword ascii
    $s2 = "g. File" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}