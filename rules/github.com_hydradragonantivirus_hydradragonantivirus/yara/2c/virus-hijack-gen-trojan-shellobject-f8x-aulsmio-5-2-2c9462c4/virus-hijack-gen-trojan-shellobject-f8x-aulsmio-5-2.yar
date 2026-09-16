rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_auLSMIo_5_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46760783fe652b02a29a17a2290480a4a8c8da6ba8eb0c7e1e37def34c9f50c2"

  strings:
    $s1  = "chocolatey - shim" fullword wide
    $s2  = "0.10.5 - shim 0.8.1" fullword wide
    $s3  = "GAttempt to add quarantined event to quarantine." fullword wide
    $s4  = "'Get' failed because the Variant is not the correct type." fullword ascii
    $s5  = " is being used after it has been destroyed." fullword ascii
    $s6  = "2Microsoft Equation Edito" fullword wide
    $s7  = "GEvent Buffer is full" fullword wide
    $s8  = "G!!UNAVAILABLE!!" fullword wide
    $s9  = " 2017 Chocolatey Software, Inc.. Copyright " fullword wide
    $s10 = "Variant type ID is invalid.  This is probably because the variant object is being used without being properly initialized, or it" ascii
    $s11 = "Variant type ID is invalid.  This is probably because the variant object is being used without being properly initialized, or it" ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}