import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72853156_219_1_Trojan_Danger_Tro_448 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72853156_219_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_235_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_247_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_254_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_260_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_266_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b1b9e6d7746e75bb2afb349944369a98bc5db2985541f0d842cf07779027732f"
    hash2       = "b6e69f0bc6416a8ff1433f164b41de1ed2a903c021df37be90019c7567929a7e"
    hash3       = "d72c71a1df5eb922c932b0d519832e74a66a8815a1fcbd4a354ae6fd6ab8c533"
    hash4       = "b17ad2cf8341905debceef37e4437fc23b5f5aa4f48e5385c9c842481e87f36b"
    hash5       = "69b2535a105c6709514a9cccb9597bc548cbe1b38056e9d2187bc9d7c131b872"
    hash6       = "a0dd94c7b83aad99bdba58eb904b7e3fb10a6ff2c3d4841dc41583880b534122"

  strings:
    $s1  = "purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall beamqqv" ascii
    $s2  = "aqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamq" ascii
    $s3  = "qvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqcompany is defined as a user able to initiate, or host, a web conference and also par" ascii
    $s4  = "not apply to you if you live in Japan or acquired the software while you lived in Japan.qqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamq" ascii
    $s5  = "purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall beamqqv" ascii
    $s6  = "ny given time. Professional Users 2003 " fullword ascii
    $s7  = "electronically (not manually entered by licensed professional users) through EDI, XML or other electronic means includingmqqvaqq" ascii
    $s8  = "electronically (not manually entered by licensed professional users) through EDI, XML or other electronic means includingmqqvaqq" ascii
    $s9  = "ticipate in a web conference; all" fullword ascii
    $s10 = "software license, for a refund or credit.sqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaq" ascii
    $s11 = "mqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvOrder Line: is defined as the total number of order entry line items pro" ascii
    $s12 = "software license, for a refund or credit.sqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaq" ascii
    $s13 = "s ability toSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqq" ascii
    $s14 = "not apply to you if you live in Japan or acquired the software while you lived in Japan.qqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamq" ascii
    $s15 = "cessed by the program during a 12 month period." fullword ascii
    $s16 = "qdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvwhether or not the individual is actively using the programs at a" ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "78068e9a818b0f3dbc85fad9bd4be634" and (8 of them)
    ) or (all of them)
}