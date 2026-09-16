rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4eb4b268f41149d06dab2c043587e540ed883b4958f879185b85e02d0db42e91"

  strings:
    $s1 = "Copyright 2014 AiosrdKofdr" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}