rule Virus_Hijack_Gen_Trojan_ShellObject_m8Z_amOckRg_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.m8Z@amOckRg_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c5b341bcb10d1136beecaac7431f9cb969052259b10662fd037fce3629d6eac"

  strings:
    $s1 = "olhelp32S:phot" fullword ascii
    $s2 = "*VERB){" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}