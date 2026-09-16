rule Virus_Hijack_Trojan_GenericKDZ_98113_327_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_327_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6313281c90f78039ba2f7393510f5f16c8b18ab22b6ce3bb40bbfde68591beaa"

  strings:
    $s1 = "lILe;l" fullword ascii
    $s2 = "Vl}PavE" fullword ascii
    $s3 = "kuBA,;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}