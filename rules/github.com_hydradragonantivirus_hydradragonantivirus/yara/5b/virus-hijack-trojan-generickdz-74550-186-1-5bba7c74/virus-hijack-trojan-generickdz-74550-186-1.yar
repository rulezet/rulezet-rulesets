rule Virus_Hijack_Trojan_GenericKDZ_74550_186_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_186_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fee592dac72ce36861cc05efd38e94e8f7d4ffdfe435e69cf41859f0ad50eb0f"

  strings:
    $s1 = "Pega(H" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}