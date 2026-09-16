rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_aarXj5d_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@aarXj5d_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40e67441ee3240a12ad9e6212da110061a5078426ea174fea5fef94f47c67001"

  strings:
    $s1 = "1?purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}