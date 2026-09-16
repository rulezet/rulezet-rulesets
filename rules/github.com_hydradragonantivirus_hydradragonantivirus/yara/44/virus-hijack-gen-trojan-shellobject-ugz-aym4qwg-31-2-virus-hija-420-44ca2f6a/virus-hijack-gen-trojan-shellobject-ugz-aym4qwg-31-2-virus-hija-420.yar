rule _Virus_Hijack_Gen_Trojan_ShellObject_uGZ_ayM4QWg_31_2_Virus_Hija_420 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_31_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_32_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_33_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_34_2.vir, Virus.Infector_Dropped.Trojan.Dropper.Delf.BB.vir, Virus.Infector_Trojan.Dropper.Delf.BB.vir, Virus.Infector_Trojan.Dropper.Delf.BB_1.vir, Virus.Infector_Trojan.Dropper.Delf.BB_2.vir, Virus.Infector_Trojan.Dropper.Delf.BB_3.vir, Virus.Infector_Trojan.Dropper.Delf.BB_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7980b88ff55481b3c16f90d69eb2af02dffff5934dc6bf97be2c3cfa328993c0"
    hash2       = "830a3b40ca5dc64764412b4634aa5a83a7d615052b010b853c19be614d066acb"
    hash3       = "56ea165afd9e518da0becb3b17f21cd1726d0a04a8607c8bdab545eb4bcf8576"
    hash4       = "a28aca1e14dd45c40c95cb0f15fc574313eb1ca464517d5b014f5996d4a7e741"
    hash5       = "1e66229eef870849d6ba4e6b96e57675101c2d979e3b15a698cfbd9ba6fdd128"
    hash6       = "534ed34e9b9dbb074f67b1598c402667dc247a45bfb4a2dbc9dd9c16e72edc6f"
    hash7       = "d37e1b2c720b771ff71a41976b32ec46fe56b684c10d1c1fe90453e2e05e6f15"
    hash8       = "30e453b4c98c5d8c72e921cd55b27a2da9bea782d2ea3adb268427e467467c73"
    hash9       = "16b8bb94d37286dfc1b18009d51fde49b370d82851c95ce622aec843f12f8095"
    hash10      = "30ae840ad54c2adf2163c269b1c11d26b80fa67f9e9ffe88ca79f40e107b1096"

  strings:
    $s1 = " :You are already logged in." fullword ascii
    $s2 = " :Wrong Password." fullword ascii
    $s3 = " :You are now logged in." fullword ascii
    $s4 = " :You are now logged out." fullword ascii
    $s5 = " :You are not logged in." fullword ascii
    $s6 = "QUIT :Aids infected my brain and my butt." fullword ascii
    $s7 = " :Error!" fullword ascii
    $s8 = "To connect, type" fullword ascii
    $s9 = "PONG :" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}