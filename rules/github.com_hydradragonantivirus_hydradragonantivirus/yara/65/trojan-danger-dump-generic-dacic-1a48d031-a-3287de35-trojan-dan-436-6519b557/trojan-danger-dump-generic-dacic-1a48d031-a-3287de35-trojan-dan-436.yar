rule _Trojan_Danger_Dump_Generic_Dacic_1A48D031_A_3287DE35_Trojan_Dan_436 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Dump.Generic.Dacic.1A48D031.A.3287DE35.vir, Trojan.Danger_Dump.Generic.Dacic.1A48D031.A.B69FE9A0.vir, Trojan.Danger_Dump.Generic.Dacic.1A48D031.A.B69FE9A0_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_400_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_40_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07d2040f8f0e085c4e76f21469dc6a0ac958221c084809ebc6d8e0773fb4db52"
    hash2       = "63604873b10a9b20a9cd9ec3ad76ee64f4dbbe1f1b968be00df5a4bf08d42f74"
    hash3       = "eebeb914554bf503f690fab8406ee8692863b350188b3e18dbec8db1241a12df"
    hash4       = "da8fb08cbdb6d52a34697e3b9d27a3dbb2e7d715703178aa353e04ddcef01afc"
    hash5       = "f7b4e750f2379fb56a70e2018275b965f8f53bfc37dc3d597bdfb4d77842c9d5"

  strings:
    $s1 = "- (C) Copyright 1998 by ANAKiN " fullword ascii
    $s2 = "PE-PACK: IMPORT LDR ERROR" fullword ascii
    $s3 = "Anti Virus&Rootkit Tools" fullword wide
    $s4 = "PE-PACK: MEMORY ALERT" fullword ascii
    $s5 = "Ordinal %.4Xh not found in %s" fullword ascii
    $s6 = "(C) 2008-2012 linxer. All Rights Reserved." fullword wide
    $s7 = "2011-12-03 Build" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}