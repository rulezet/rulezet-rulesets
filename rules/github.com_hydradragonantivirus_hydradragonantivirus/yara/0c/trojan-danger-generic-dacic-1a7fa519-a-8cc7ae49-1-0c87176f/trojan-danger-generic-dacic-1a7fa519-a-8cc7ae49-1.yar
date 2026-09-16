rule Trojan_Danger_Generic_Dacic_1A7FA519_A_8CC7AE49_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.8CC7AE49_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9eaacb523df03205487116dc5c1f0d873f6daad67d4a88ca90cd3b2a3c035042"

  strings:
    $s1 = "/University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}