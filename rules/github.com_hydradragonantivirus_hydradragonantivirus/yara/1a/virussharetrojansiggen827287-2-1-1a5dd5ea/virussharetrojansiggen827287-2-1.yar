rule VirusShareTrojanSiggen827287_2_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen827287_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3236aee6db7f0f80eb9df9761afd6aff45edcb527c7deb9048c46e6cc84f454"

  strings:
    $s1 = "F_controlfp_s(((void *)0), 0x00010000, 0x00030000)" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}