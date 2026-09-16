rule Virus_Hijack_Trojan_GenericKDZ_105924_175_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_175_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7108d55b558c94e0fdaa89442bd1cfabb3f185e7b409392611e9d949788f37e3"

  strings:
    $s1 = "CreateFile Error" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}