rule Virus_Hijack_Trojan_GenericKDZ_74550_265_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.74550_265_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e91dff37b1eba7aebc18feaf013b2de406609e010e7ea71196ff4cca84b7d4a"

  strings:
    $s1 = "ALeE!>tm" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}