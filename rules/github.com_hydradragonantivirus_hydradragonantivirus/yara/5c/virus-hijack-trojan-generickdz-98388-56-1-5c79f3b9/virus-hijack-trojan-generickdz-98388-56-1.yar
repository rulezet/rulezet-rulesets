rule Virus_Hijack_Trojan_GenericKDZ_98388_56_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_56_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8963e3c3efbc098a0bb512216f9c91eac90a0ae0f97491f1dc814035d281eeea"

  strings:
    $s1 = "<tuBe'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}