rule Virus_Hijack_Gen_Trojan_ShellObject_pyZ_aOWVavp_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.pyZ@aOWVavp_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22487c9b65b6975d3acdd9937d5bbb7c90dd274319b258f9c7ff450f56e40203"

  strings:
    $s1 = "l]soKa" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}