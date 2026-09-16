import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72677122_107_1_Trojan_Hooker_Gen_133 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72677122_107_1.vir, Trojan.Hooker_Gen.Variant.Barys.862.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b3664b3522b3df991e05e836b423790fb294f54f624f2f55774912d786a6216"
    hash2       = "ff4b96872c9e0226ef5695f1d578a66a0ebc9d6c91602b26c2a9f874154e242c"

  strings:
    $s1  = "arbalist" fullword ascii
    $s2  = "Aeronaut" fullword ascii
    $s3  = "Cellulose" fullword ascii
    $s4  = "Fruiting" fullword ascii
    $s5  = "Aquarian" fullword ascii
    $s6  = "Enlisted" fullword ascii
    $s7  = "facies" fullword ascii
    $s8  = "dyspeptically" fullword ascii
    $s9  = "WebZen mu main" fullword wide
    $s10 = "Adjure" fullword ascii
    $s11 = "Cabalism" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "aecd90465f4a4fe7d70f2642938c82d8" and (8 of them)
    ) or (all of them)
}