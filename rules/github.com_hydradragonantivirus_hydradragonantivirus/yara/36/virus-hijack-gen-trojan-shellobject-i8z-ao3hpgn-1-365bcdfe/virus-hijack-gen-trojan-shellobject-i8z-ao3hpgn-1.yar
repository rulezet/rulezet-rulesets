rule Virus_Hijack_Gen_Trojan_ShellObject_i8Z_aO3hPGn_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.i8Z@aO3hPGn_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "154719724fd743ae39f33c731dcecd55d73773e50ee798663a91ff77325388f3"

  strings:
    $s1 = "atIP[yG" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}