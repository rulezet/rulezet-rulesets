rule Trojan_Danger_Generic_Dacic_1A7FA519_A_5AEA6884_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.5AEA6884_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "750098f0b3f8a75ca566e27dec3dc37c1133aa8da9d16ba1bfce2d75bfe28a25"

  strings:
    $s1 = "Rvirtualization, see the Additional Terms." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}