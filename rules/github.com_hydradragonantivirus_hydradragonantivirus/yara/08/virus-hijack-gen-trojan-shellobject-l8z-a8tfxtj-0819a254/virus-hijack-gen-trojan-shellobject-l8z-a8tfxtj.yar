rule Virus_Hijack_Gen_Trojan_ShellObject_l8Z_a8TFxTj {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.l8Z@a8TFxTj.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "90e2093c88d745f6e9860bdf541573ba17d6d80537c4057753ed86f16a513984"

  strings:
    $s1 = "[month pe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}