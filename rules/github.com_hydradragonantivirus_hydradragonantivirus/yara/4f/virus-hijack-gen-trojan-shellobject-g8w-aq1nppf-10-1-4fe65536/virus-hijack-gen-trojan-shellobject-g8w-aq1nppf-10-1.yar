rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aq1NpPf_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aq1NpPf_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5adbef08bba8929b4e5daca8dd9463f6fd4f2961c8e45170584001a68217df9e"

  strings:
    $s1  = "ex27a Version 1.0" fullword wide
    $s2  = "UOLE initialization failed.  Make sure that the OLE libraries are the correct version.9This server can only be run from a contai" wide
    $s3  = "Initial default text" fullword ascii
    $s4  = "About ex27a" fullword wide
    $s5  = "ex27a Document" fullword wide
    $s6  = "Print Preview/Update the container to show any changes" fullword wide
    $s7  = "Update<Save a copy of the active document with a new name" fullword wide
    $s8  = "o GuLF{&" fullword ascii
    $s9  = "ex27a MFC Application" fullword wide
    $s10 = "ex27a Application" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}