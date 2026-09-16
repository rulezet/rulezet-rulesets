rule Virus_Hijack_Trojan_GenericKDZ_103285_80 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_80.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "697774ed048b8347a01b5db3c4ea49c26529ac2ee5253e6e77677e44ba2bd8f3"

  strings:
    $s1 = "[virtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}