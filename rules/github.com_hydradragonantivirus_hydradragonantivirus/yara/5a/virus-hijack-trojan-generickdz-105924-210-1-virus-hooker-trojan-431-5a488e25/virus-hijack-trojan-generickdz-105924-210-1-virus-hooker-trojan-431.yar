rule _Virus_Hijack_Trojan_GenericKDZ_105924_210_1_Virus_Hooker_Trojan_431 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.GenericKDZ.105924_210_1.vir, Virus.Hooker_Trojan.GenericKD.64731121_1.vir, Virus.Infector_Gen.Trojan.Malware.1q3@aunLb5ni_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bea1786e9ec41a6684ff7a328455227989a9929b7295b1ec9b557a916c9f42df"
    hash2       = "bf6b57ff4efd90fcb7a9358ad977082028555ac9f26c37dd44b90f47a2fcc96f"
    hash3       = "85fc817c1c8dda19e804a3aaa4081ca4f0824b066ad3e0bbc5a67e4645b7fe98"

  strings:
    $s1  = "srctool: -u is not available when the target is a stream file." fullword ascii
    $s2  = "srctool: Couldn't call dbghelp.dll" fullword ascii
    $s3  = "srctool: dumps source information from a pdb" fullword ascii
    $s4  = " print -o " fullword ascii
    $s5  = "         optional '-n' shows version control commands and output while extracting" fullword ascii
    $s6  = "%s: none of the %d source files are indexed" fullword ascii
    $s7  = "%s: %d source files were extracted" fullword ascii
    $s8  = "%s: %d source files are indexed" fullword ascii
    $s9  = "%s: %d source files were found" fullword ascii
    $s10 = "         optional '-r' dumps raw source data from the pdb" fullword ascii
    $s11 = "         you must specify a pdb or srcsrv stream file on the command line" fullword ascii
    $s12 = "srctool: error listing the source indexed files" fullword ascii
    $s13 = "         optional '-c displays only the count of indexed files - no detail" fullword ascii
    $s14 = "srctool: Couldn't load %s" fullword ascii
    $s15 = "srctool: Couldn't find SymAddSourceStream()" fullword ascii
    $s16 = "srctool: Couldn't find %s" fullword ascii
    $s17 = "not indexed" fullword ascii
    $s18 = "%s is not a valid directory." fullword ascii
    $s19 = "%s is not source indexed" fullword ascii
    $s20 = "Couldn't extract %s" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}