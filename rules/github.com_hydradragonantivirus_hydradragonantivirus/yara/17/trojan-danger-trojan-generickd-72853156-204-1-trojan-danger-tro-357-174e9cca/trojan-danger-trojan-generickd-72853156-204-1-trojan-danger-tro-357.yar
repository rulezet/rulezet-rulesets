import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72853156_204_1_Trojan_Danger_Tro_357 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72853156_204_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_224_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_24_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed12cc79b51bac392ef1e2abb85a52eae79dd5fe4a0ae1b2c83c4645875a8bc8"
    hash2       = "db33bb2ca557f0852a656275aebd0ef5d4ffc483c768eebfd25fc013916e3626"
    hash3       = "4b52020477ed4937f41533bf9063f8a3e8d9b0254fcc93067f13085d9c907717"

  strings:
    $s1 = "may embed fonts in content only as permitted by the embedding restrictions in the fonts.qamqqvaqqdSysqamqqvaqqdS" fullword ascii
    $s2 = "ective date of the ordering document." fullword ascii
    $s3 = "MERCHA NTA BILITY, FITNESS FOR A PARTICULAR PURPOSE, A ND NON-INFRINGEMENT. IFSysqamqqvaqqdSysqemucwtlSysqemoaafvSysqemexnqqSysq" ascii
    $s4 = "dSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqTechnical support is effective upon shipment, or if shipment is not required, upon the eff" ascii
    $s5 = "qqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysCONSUMER RIGHTS UNDER YOUR LOCAL LAWS WH" ascii
    $s6 = "qqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysCONSUMER RIGHTS UNDER YOUR LOCAL LAWS WH" ascii
    $s7 = "dSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqTechnical support is effective upon shipment, or if shipment is not required, upon the eff" ascii
    $s8 = "ICH THIS AGREEMENT CANNOT CHA NGE. TO" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "665059d79bf75e9925a053185ffaa715" and (all of them)
    ) or (all of them)
}