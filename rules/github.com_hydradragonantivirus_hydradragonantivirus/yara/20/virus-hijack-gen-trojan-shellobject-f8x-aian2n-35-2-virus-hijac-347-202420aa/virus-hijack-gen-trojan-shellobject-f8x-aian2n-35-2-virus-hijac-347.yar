import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_aian2n_35_2_Virus_Hijac_347 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_35_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_36_2.vir, Virus.Hijack_Trojan.GenericKDZ.105924_247_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_248_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91847c696842bcfad2fa74980d3fbe89ebae66e9869fc2860125112cb387565a"
    hash2       = "ba1618e9ac1af3de38516c3be063afeebe03e25c01978383a6905ff015a930b8"
    hash3       = "944abbcf2469cb1cd239f9d4339e158992a82fc4b19329452fd81b78a842b2d8"
    hash4       = "f547fa2e4524674fb37a83ed6a4bae205722f602f7a46f4140f0be20e91ebfca"

  strings:
    $s1  = "Offset - DEC" fullword wide
    $s2  = "Offset - HEX" fullword wide
    $s3  = "Selected Byte" fullword ascii
    $s4  = "Find Hex Values" fullword ascii
    $s5  = "Next bookmark" fullword ascii
    $s6  = "Previous bookmark" fullword ascii
    $s7  = "&About Hex Editor" fullword ascii
    $s8  = "Find and Replace Text" fullword ascii
    $s9  = "Symbol'" fullword ascii
    $s10 = "Find and Replace Hex Values" fullword ascii
    $s11 = "Bytes per Page" fullword ascii
    $s12 = "Courier New;" fullword ascii
    $s13 = "unsigned char data[" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "834e5f580ccf4e130164442c301d9e99" and (8 of them)
    ) or (all of them)
}