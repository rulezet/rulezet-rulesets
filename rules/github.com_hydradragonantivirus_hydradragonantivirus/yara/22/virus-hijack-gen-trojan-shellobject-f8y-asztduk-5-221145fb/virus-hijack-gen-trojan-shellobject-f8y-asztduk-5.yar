rule Virus_Hijack_Gen_Trojan_ShellObject_f8Y_aSZtDuk_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1b833076837f197d3d442f334198fece17aee1a0feb5447bd7b0ea857ae7bde2"

  strings:
    $s1 = "0or service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}