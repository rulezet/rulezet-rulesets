rule Virus_Hijack_Trojan_GenericKDZ_103285_756 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_756.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79d2637750d03098fd0b8f5adc11d5faaac41aed6099256caa26d552439744b1"

  strings:
    $s1 = "}(University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}