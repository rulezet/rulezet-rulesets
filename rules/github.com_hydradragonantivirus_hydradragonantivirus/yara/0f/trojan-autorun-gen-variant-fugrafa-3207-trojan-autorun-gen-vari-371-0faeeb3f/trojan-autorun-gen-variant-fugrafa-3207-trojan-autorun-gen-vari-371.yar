import "pe"
rule _Trojan_Autorun_Gen_Variant_Fugrafa_3207_Trojan_Autorun_Gen_Vari_371 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Gen.Variant.Fugrafa.3207.vir, Trojan.Autorun_Gen.Variant.Fugrafa.3207_1.vir, Trojan.Autorun_Gen.Variant.Fugrafa.3207_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8W@aGAMRTl_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3e23f2a4b59a7d4872fe2df08cdaf1ac11e866a8475337c92050b30bfeb77a89"
    hash2       = "4018ca41508e31e4461dd78c8eccfae308f952c441e6c8b040127f9437e48e9d"
    hash3       = "7383c923b951e17815b2de8d795e3197ddfe79800cd79145e517a3909d36c06a"
    hash4       = "ef95ceaeaf01a38e1b6352269b6b2fd6168edc38f03cff5bc236bfbea3c42272"

  strings:
    $s1 = "A required .DLL file, %hs, was not found." fullword ascii
    $s2 = "This program was packed with a demo version of eXPressor" fullword ascii
    $s3 = "linked to missing export %hs:%hs." fullword ascii
    $s4 = "Error Starting Program" fullword ascii
    $s5 = "linked to missing export %hs:0x%04x." fullword ascii
    $s6 = "The %hs file is " fullword ascii
    $s7 = ">CLICK OPEN PAGE" fullword ascii
    $s8 = "Error bad relocation pointer:" fullword ascii
    $s9 = "Unexpected relocation type:" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "71354f5f9ccb75bff3123274b97c2493" and (all of them)
    ) or (all of them)
}