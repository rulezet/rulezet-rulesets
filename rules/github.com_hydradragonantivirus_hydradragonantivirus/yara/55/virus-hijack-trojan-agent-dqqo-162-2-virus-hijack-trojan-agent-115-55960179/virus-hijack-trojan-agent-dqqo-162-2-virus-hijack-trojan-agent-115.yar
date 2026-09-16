import "pe"
rule _Virus_Hijack_Trojan_Agent_DQQO_162_2_Virus_Hijack_Trojan_Agent__115 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.Agent.DQQO_162_2.vir, Virus.Hijack_Trojan.Agent.DQQO_163_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdebfb2008f0cdd769d922a926c0bd74ec2eb682ed935aeb18551018e40d7f5f"
    hash2       = "7cab2b38473191d9c8a6d48a0dd0d0e229453872e6c0c1fbb6287f30cd565894"

  strings:
    $s1  = "Failed to get resource address." fullword wide
    $s2  = "Failed to get read/write handle" fullword wide
    $s3  = "Failed to get pointer to resource data" fullword wide
    $s4  = "An error occurred while modifying the resource directories. " fullword wide
    $s5  = "Error in RVA_to_Offset function: " fullword wide
    $s6  = "Error in Offset_to_RVA function: " fullword wide
    $s7  = "Failed to load resource" fullword wide
    $s8  = "SimpleXOR Error Procedure" fullword wide
    $s9  = " Please make sure neither of the specified files are in use." fullword wide
    $s10 = "No existing resources in source file" fullword wide
    $s11 = "Source file doesn't exist" fullword wide
    $s12 = "An error occurred while locating the resource tree. " fullword wide
    $s13 = "An error occurred while locating the icon resources. " fullword wide
    $s14 = "Failed to locate resource entry" fullword wide
    $s15 = "Failed to locate resource." fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "a4907116c1f567ab9bb5e3979d24b0b8" and (8 of them)
    ) or (all of them)
}