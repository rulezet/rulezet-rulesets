rule Virus_Hijack_Trojan_GenericKDZ_98113_115 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_115.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f30fd4375f360a3f331875799663903b26eb5a3a244fcb005e573bbf8bca1c31"

  strings:
    $s1 = "Ryour order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}