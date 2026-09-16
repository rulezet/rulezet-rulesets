rule Virus_Hijack_Gen_Trojan_ShellObject_p4Z_aG4Sr2m {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.p4Z@aG4Sr2m.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d32ec090c2156489475fdc3625c2cad950a212902938743fab947240ae0cd588"

  strings:
    $s1 = "u%that party must agree that this agreement applies to the transfer and use of the software. You may not" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}