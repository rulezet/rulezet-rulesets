import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_auLSMIo_7_2_Virus_Hijac_96 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_7_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "adaba13f9a43428949e9c81755f49e2aab723c88373771e518fd29d81c96a90d"
    hash2       = "b12935f20c6bfcb2009d48462f248b15d7030a105694721bc8cdd57f4856ec59"

  strings:
    $s1  = "Failed to get Root element " fullword ascii
    $s2  = "Failed to get count " fullword ascii
    $s3  = "Failed to load function from HDUWP DLL from path %s" fullword wide
    $s4  = "getting table " fullword ascii
    $s5  = "@Failed to open PIM database with error %d." fullword wide
    $s6  = "service installed status is " fullword ascii
    $s7  = "Failed to receive response from AID" fullword ascii
    $s8  = "Checking if service is installed or not " fullword ascii
    $s9  = "SELECT COUNT(DISTINCT value) FROM domain_data where key = 'LicensingCode'" fullword ascii
    $s10 = "Query Excecution Failed" fullword ascii
    $s11 = "Opening Database Failed" fullword ascii
    $s12 = "response is " fullword ascii
    $s13 = "Checking for installation criteria!" fullword ascii
    $s14 = "Acrobat Pro is not present " fullword ascii
    $s15 = "Acrobat Std is present " fullword ascii
    $s16 = "Acrobat Pro is present " fullword ascii
    $s17 = "Acrobat Std is not present " fullword ascii
    $s18 = "Count of Apps in PCD " fullword ascii
    $s19 = "Opening Database SuccessFul" fullword ascii
    $s20 = "Adobe apps found in AID " fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "b941ddedcc51e5706d41335adb4e6b2a" and (8 of them)
    ) or (all of them)
}