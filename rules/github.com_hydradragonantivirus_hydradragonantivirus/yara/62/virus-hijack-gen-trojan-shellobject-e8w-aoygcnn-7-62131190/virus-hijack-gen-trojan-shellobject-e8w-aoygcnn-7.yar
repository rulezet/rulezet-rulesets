rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aOygCnn_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aOygCnn_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "23ff0735de8ddb95c190037f5282ec21b0c976352f2c751bbf91de42b693a2d4"

  strings:
    $s1 = "jEsT%_gT)E{" fullword ascii
    $s2 = "jEsT%_gT'Ox" fullword ascii
    $s3 = "$hundred euros) in all purchase orders transacted" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}