rule Virus_Hijack_Trojan_GenericKDZ_105924_614_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_614_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f59a7c194fad4fd4964ff4b87814067899a0d1dcbdfae408937d20379177ad6f"

  strings:
    $s1 = "}\"Ropp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}