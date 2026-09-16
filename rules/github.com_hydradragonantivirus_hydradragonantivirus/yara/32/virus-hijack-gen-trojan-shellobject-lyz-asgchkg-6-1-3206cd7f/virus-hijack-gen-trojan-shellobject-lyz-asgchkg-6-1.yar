rule Virus_Hijack_Gen_Trojan_ShellObject_lyZ_aSgChKg_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.lyZ@aSgChKg_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "645262b3ba493c730e45d202a4b303ca2afd198d4878545bf90788cf1b8123b2"

  strings:
    $s1  = "Poisonous" fullword ascii
    $s2  = "Stinging" fullword ascii
    $s3  = "FrameworkDisplayName.NET Framework 4 Client Profile1" fullword ascii
    $s4  = "Breeding" fullword ascii
    $s5  = "Irritant" fullword ascii
    $s6  = "Species" fullword ascii
    $s7  = "Medicinal" fullword ascii
    $s8  = "Nocturnal" fullword ascii
    $s9  = "Diurnal" fullword ascii
    $s10 = "Kingdom&" fullword ascii
    $s11 = "Phylum(" fullword ascii
    $s12 = "Biting" fullword ascii
    $s13 = "Genus$" fullword ascii
    $s14 = "F@Soft" fullword wide
    $s15 = "@E?GrAm" fullword ascii
    $s16 = " F@Soft" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}