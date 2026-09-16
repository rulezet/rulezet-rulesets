rule Virus_Hijack_Gen_Trojan_ShellObject_EuZ_aiy413e_7 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.EuZ@aiy413e_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c851e043902096b78a8a84999525b632a29e105182db1012aafb094ad4f80777"

  strings:
    $s1 = "@BesA*2" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}