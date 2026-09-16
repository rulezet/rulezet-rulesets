rule Virus_Hijack_Trojan_GenericKDZ_103285_485 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_485.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef78c8486087c67f8dfca3b73481d5817b8a78679680232897ea937e3e738194"

  strings:
    $s1 = "va neutral arbitrator, whose decision will be final except for a limited right of appeal under the Federal" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}