rule Virus_Hijack_Gen_Trojan_ShellObject_e8W_aycAujk_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8W@aycAujk_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a24db2bb886c8f5eb3c7c06db1d5caac1b631c8b653397fc2150453fdbee07a"

  strings:
    $s1 = "} rAKI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}