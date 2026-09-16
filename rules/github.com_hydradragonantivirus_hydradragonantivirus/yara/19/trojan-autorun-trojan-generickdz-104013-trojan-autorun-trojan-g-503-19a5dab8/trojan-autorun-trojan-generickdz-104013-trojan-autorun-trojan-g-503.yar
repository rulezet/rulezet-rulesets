import "pe"
rule _Trojan_Autorun_Trojan_GenericKDZ_104013_Trojan_Autorun_Trojan_G_503 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKDZ.104013.vir, Trojan.Autorun_Trojan.GenericKDZ.104013_5.vir, Trojan.Autorun_Trojan.GenericKDZ.72348_13.vir, Trojan.Autorun_Trojan.GenericKDZ.72348_26.vir, Trojan.Autorun_Trojan.GenericKDZ.72348_27.vir, Trojan.Autorun_Trojan.GenericKDZ.72348_4.vir, Trojan.Autorun_Trojan.GenericKDZ.72348_5.vir, Trojan.Autorun_Trojan.GenericKDZ.72348_8.vir, Virus.Hijack_Backdoor.Hangup.B_46_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97fd295009f2a830443dd94d87c9521f57e46e0ec92ff28ab7a29799a33e92fc"
    hash2       = "0b19303a1f9a0661f2393e2b6ea64d74b32d3641bb6bec72aae505e9ff76402d"
    hash3       = "1ee1c1641731d97a3e0c9c7a7086b99b951c9e975b78671bc28120326a27af22"
    hash4       = "ba73f0717589d271ff0ed53eba0d9e505eabfcdf2922fccc0b5fe520eed4d27c"
    hash5       = "31f612c603c458c4d9007d6ebcf678adbab6afa068309b1dfc72f15f723fecba"
    hash6       = "9a1268eb58070234068cdb346b218c1488162daf96c311fb385436d8b4963948"
    hash7       = "e770b160594e8cc22e92de3b7657964e5a024c7cab5a2604e25d5bc4986bb6c4"
    hash8       = "1913fbfbc7cf7d2b0f6e6d9f0ec1c28f2a25f30ba7e46dcfb65d3c4f19c9b0d9"
    hash9       = "ebd83ecfdcab0e825b256e7f0a084e907d5ca41c0fee16b8c3caaa192c74315e"

  strings:
    $s1  = "s confidential information shall not include information that: (a) is or becomes a part of the public domain through not separat" ascii
    $s2  = "are required to maintain licenses for the equivalent number of EAM Users licensed and" fullword ascii
    $s3  = "ion with EAM, you are required to maintain licenses for the equivalent number of EAM Users licensed and" fullword ascii
    $s4  = "njunction with EAM, you are required to maintain licenses for the equivalent number of EAM Users licensed and" fullword ascii
    $s5  = "s confidential information shall not include information that: (a) is or becomes a part of the public domain through not separat" ascii
    $s6  = "To fully understand your license grant, you need to review the definition for the" fullword ascii
    $s7  = "biological weapons proliferation, or development of missilecomputer or device. During activation, the software will automaticall" ascii
    $s8  = "biological weapons proliferation, or development of missilecomputer or device. During activation, the software will automaticall" ascii
    $s9  = "e or virtualize the components and install them on different computers. The software may" fullword ascii
    $s10 = "y contact Microsoft or its affiliate to" fullword ascii
    $s11 = "Special Editions of the software" fullword ascii
    $s12 = "other Person.n military personnel;" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "17bf95a6fc3897de4a1074e31bc023a6" and (8 of them)
    ) or (all of them)
}