rule Virus_Hijack_Trojan_GenericKDZ_103545_18 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103545_18.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f828be92ea6faa5b8787f4cadaff27849a6f4deed22d0f8320808485e19b6703"

  strings:
    $s1 = "Ujsoftware features to upgrade or fix the software and otherwise improve its products and services. In" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}