rule _Virus_Hijack_Gen_Trojan_ShellObject_e8W_a8TFxTj_5_2_Virus_Hijac_227 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.e8W@a8TFxTj_5_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_35_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_36_2.vir, Virus.Hijack_Trojan.GenericKDZ.105924_247_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_248_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c2aea531bf26ee361b3b14e7a22f91a4ff85d4fd93eca4dca85f692c123a7d50"
    hash2       = "91847c696842bcfad2fa74980d3fbe89ebae66e9869fc2860125112cb387565a"
    hash3       = "ba1618e9ac1af3de38516c3be063afeebe03e25c01978383a6905ff015a930b8"
    hash4       = "944abbcf2469cb1cd239f9d4339e158992a82fc4b19329452fd81b78a842b2d8"
    hash5       = "f547fa2e4524674fb37a83ed6a4bae205722f602f7a46f4140f0be20e91ebfca"

  strings:
    $s1  = "Find and Replace - Hex Mode" fullword ascii
    $s2  = "Find - Hex Mode" fullword ascii
    $s3  = "Find and Replace - Text Mode" fullword ascii
    $s4  = "Find - Text Mode" fullword ascii
    $s5  = "Off&set Final (Dec):" fullword ascii
    $s6  = "Available &Languages" fullword ascii
    $s7  = "String to Translate" fullword ascii
    $s8  = "&Insensitive" fullword ascii
    $s9  = "Language Pack Editor" fullword ascii
    $s10 = "ANSI Table" fullword ascii
    $s11 = "&Byte sequence:" fullword ascii
    $s12 = "Source Language:" fullword ascii
    $s13 = "Offset &Inicial (Dec):" fullword ascii
    $s14 = "Valor Hex:" fullword ascii
    $s15 = " Direction: " fullword ascii
    $s16 = "&Sensitive" fullword ascii
    $s17 = "Copi&ar para o Clipboard" fullword ascii
    $s18 = "Find  &What:" fullword ascii
    $s19 = "&Replace With:" fullword ascii
    $s20 = "New Language:" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}