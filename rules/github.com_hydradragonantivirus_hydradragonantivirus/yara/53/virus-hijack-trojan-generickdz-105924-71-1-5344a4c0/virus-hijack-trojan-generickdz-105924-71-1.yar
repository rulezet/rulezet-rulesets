rule Virus_Hijack_Trojan_GenericKDZ_105924_71_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_71_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80bfa7e3c125d6c1295c1e8432f3e47a30e6ed8c3b9b03275a1ec35809e17f3f"

  strings:
    $s1 = "MABI]%" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}