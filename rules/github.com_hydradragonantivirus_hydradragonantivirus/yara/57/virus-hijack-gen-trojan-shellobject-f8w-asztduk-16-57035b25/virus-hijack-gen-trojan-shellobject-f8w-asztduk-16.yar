rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_aSZtDuk_16 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@aSZtDuk_16.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3e5a804bba4eba8b80c423a8868f9ae3bfaa6022bb952f10df997f7b7c1ac57"

  strings:
    $s1 = "nor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}