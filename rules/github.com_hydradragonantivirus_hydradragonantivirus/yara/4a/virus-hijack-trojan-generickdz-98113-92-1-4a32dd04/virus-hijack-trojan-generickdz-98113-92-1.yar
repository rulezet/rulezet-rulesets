rule Virus_Hijack_Trojan_GenericKDZ_98113_92_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_92_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c034ffd2c7ced55b68d886ca23b0f35724286aa0e4d46988813072e08fe9366"

  strings:
    $s1 = "Avow'}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}