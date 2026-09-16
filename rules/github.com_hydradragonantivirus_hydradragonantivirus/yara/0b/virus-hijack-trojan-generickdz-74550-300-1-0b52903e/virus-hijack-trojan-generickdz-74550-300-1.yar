rule Virus_Hijack_Trojan_GenericKDZ_74550_300_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_300_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "451ee35c07f668be048437e9fc64cb21ae0f8f5187f5b8519e934356d874bcbc"

  strings:
    $s1 = "NowY@q_" fullword ascii
    $s2 = "$APii'g" fullword ascii
    $s3 = "T,+>sidi" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}