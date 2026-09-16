rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_11 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0509ec6a9e6f7918039a8c59249183504a84a0367e7d812591776fbe4c472247"

  strings:
    $s1 = " posted a" fullword ascii
    $s2 = ":` Gash" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}