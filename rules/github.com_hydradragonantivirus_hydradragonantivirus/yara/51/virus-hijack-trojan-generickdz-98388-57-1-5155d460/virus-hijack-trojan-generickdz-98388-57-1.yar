rule Virus_Hijack_Trojan_GenericKDZ_98388_57_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_57_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2ed11de3f2382505e0c041241c945e1e012cb32b5b5bfeb337b5d91b6f24f73"

  strings:
    $s1 = "!pAWN<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}