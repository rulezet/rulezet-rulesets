rule Trojan_Danger_Generic_Dacic_1A7FA519_A_64A1F843_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.64A1F843_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e9d27f941588afe7747681b71d322d6177d6e98528128e5aead02049a304a6cb"

  strings:
    $s1 = "c*PlaY s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}