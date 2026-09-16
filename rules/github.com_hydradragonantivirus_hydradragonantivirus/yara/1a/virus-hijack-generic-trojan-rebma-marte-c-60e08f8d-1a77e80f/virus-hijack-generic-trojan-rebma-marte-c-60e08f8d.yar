rule Virus_Hijack_Generic_Trojan_Rebma_Marte_C_60E08F8D {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Generic.Trojan.Rebma.Marte.C.60E08F8D.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc13dd011ca40e56769a5427590fe79540192a185adca2a9478d7638b0f8d9ce"

  strings:
    $s1 = "Amber - Reflective PE Packer" fullword wide
    $s2 = "AMBER - Reflective PE Packer" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}