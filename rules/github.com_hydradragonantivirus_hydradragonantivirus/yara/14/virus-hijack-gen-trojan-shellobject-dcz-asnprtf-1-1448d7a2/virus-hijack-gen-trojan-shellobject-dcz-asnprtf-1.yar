rule Virus_Hijack_Gen_Trojan_ShellObject_DCZ_aSNPrTf_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DCZ@aSNPrTf_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "986da1d270a74194dd159733e28d84b9a2b8a76440324a2c3b268e30088704f6"

  strings:
    $s1 = "access the documentation online at http://oracle.com/contracts. Se" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}