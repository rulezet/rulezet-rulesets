import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_aian2n_31_2_Virus_Hijac_234 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_31_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_32_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_33_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_34_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9df77ed62899a0969a6a19c81b7a49ae6353610c034ded95c47fdb72641043d8"
    hash2       = "65b1ddcda12c0f9442d2a27f30cf1a2f0d7031ed420c8095133cdf078d0a7414"
    hash3       = "a9eb9352cec6b7136eaccdd0e767ea8bfaf860840291def7989ab3b4ebdc6cac"
    hash4       = "3ebaa75787bebaf0887cc5c0da04be3bbfa1498ac190a497ece5783301239462"

  strings:
    $s1  = "No data to process." fullword wide
    $s2  = "Failed to create hash object key." fullword wide
    $s3  = "Shutdown the operating system." fullword ascii
    $s4  = "All API Network - VB6 reference " fullword ascii
    $s5  = "Return length - " fullword wide
    $s6  = "Current Min - " fullword wide
    $s7  = "Current Max - " fullword wide
    $s8  = "About - " fullword wide
    $s9  = "Deletes a particular key or a complete section within an INI file." fullword ascii
    $s10 = "Failed to retrieve hashed data." fullword wide
    $s11 = "Failed to hash data." fullword wide
    $s12 = "Determines if an INI file already exist.  If it does not, one is created." fullword ascii
    $s13 = "Saves a value to a specific key in an INI file." fullword ascii
    $s14 = "Incoming array has not been properly initialized." fullword wide
    $s15 = "Incoming array has not been properly prepared." fullword wide
    $s16 = "An unknown error occurred while retrieving" fullword wide
    $s17 = "Planet Source Code for Visual Basic" fullword ascii
    $s18 = "Obtains the name of a specific section in an INI file." fullword ascii
    $s19 = "Browse for a folder" fullword wide
    $s20 = "VBnet  API code snippets for VB6" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "65eb9924399bd800c617bf5cbb0996ca" and (8 of them)
    ) or (all of them)
}