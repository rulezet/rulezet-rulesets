rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aWD2a0g_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aWD2a0g_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c58c4622bd84dffa7a3c8215da467242baa6cb7d05ef6a07828e7cdaae998ef6"

  strings:
    $s1 = "Patrilocal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}