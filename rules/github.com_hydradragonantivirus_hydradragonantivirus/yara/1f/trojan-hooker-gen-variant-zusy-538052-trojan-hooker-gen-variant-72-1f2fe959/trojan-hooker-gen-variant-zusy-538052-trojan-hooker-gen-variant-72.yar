import "pe"
rule _Trojan_Hooker_Gen_Variant_Zusy_538052_Trojan_Hooker_Gen_Variant_72 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Gen.Variant.Zusy.538052.vir, Trojan.Hooker_Gen.Variant.Zusy.538052_1.vir, Trojan.Sysbot_Gen.Variant.Ransom.VirLock.100_31_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "641739bce8b60a68a942bd3236d5dca4e336eb9b590300c234861898aa1220ec"
    hash2       = "b23d2d39d039f987147e6c7b29934603fe9cf420006e0e6fdaf3ef5730d7e272"
    hash3       = "3c0e0983930fb126ae6eeb4f6e3f00e49acdce95fada309f72357f8bea0166a6"

  strings:
    $s1  = "Climatologist" fullword ascii
    $s2  = "inundant" fullword ascii
    $s3  = "Emulsoid" fullword ascii
    $s4  = "Burgomaster" fullword ascii
    $s5  = "Divagation" fullword ascii
    $s6  = "Queasily" fullword ascii
    $s7  = "aboral" fullword ascii
    $s8  = "aminic" fullword ascii
    $s9  = "catmint" fullword ascii
    $s10 = "tubercule alle'" fullword wide
    $s11 = "oire censurer bu^cher 2006" fullword wide
    $s12 = "Aghast" fullword ascii
    $s13 = "Choosy" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "c39fdee7260591b3c2d2595d68e7f362" and (8 of them)
    ) or (all of them)
}