rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aKzODno_18_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aKzODno_18_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbeb955ca92e76bc50febf4d0c529628286d0ea03cf837f682df9d8b572aa212"

  strings:
    $s1 = "munity" fullword ascii
    $s2 = "chipyahooa8s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}