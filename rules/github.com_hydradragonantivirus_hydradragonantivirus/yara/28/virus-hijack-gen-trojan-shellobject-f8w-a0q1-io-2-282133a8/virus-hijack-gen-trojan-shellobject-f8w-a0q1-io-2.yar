rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_a0q1_io_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@a0q1@io_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f22fc9aa4ce82e7761748fc1e7c2b1a698d80a6df75ccd797aea83d3acd0dd65"

  strings:
    $s1 = "Unor service that is subject to a discount or a pr" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}