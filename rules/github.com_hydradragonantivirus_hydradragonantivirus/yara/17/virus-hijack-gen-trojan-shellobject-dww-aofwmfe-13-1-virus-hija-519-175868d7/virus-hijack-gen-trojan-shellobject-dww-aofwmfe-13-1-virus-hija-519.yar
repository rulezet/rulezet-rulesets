import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_13_1_Virus_Hija_519 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_13_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_14_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_15_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46c2742af9d6340c4181d11926cfa4d00c75bcf4385140d57929d707c166053f"
    hash2       = "704ee17ae79cb7aaaaadcdfef4a96feef244f2795e4e16c9df7342eae4a44dbe"
    hash3       = "72964cbf800fe900c7e6b8f8573a49ba4da2e620e2553a27d2058024809221f3"
    hash4       = "a70c2ccb53dbe7a79c06e391d1896615781406562d4976094ede48bc568a48cf"

  strings:
    $s1 = "(never used) type $c1" fullword wide
    $s2 = "(ext8,ext16,ex32) type $c7,$c8,$c9" fullword wide
    $s3 = "masterKey can not be null or empty." fullword wide
    $s4 = "Invalid message authentication code (MAC)." fullword wide
    $s5 = "input can not be null." fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "f34d5f2d4577ed6d9ceec516c1f5a744" and (all of them)
    ) or (all of them)
}