rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_35_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_35_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9edb2b372207b84a1539add3cb3d56f70d0b9408df7fd64b1b2c25314d2346f"

  strings:
    $s1  = "(Visual C++ %d.%d)" fullword ascii
    $s2  = "  -j  junk paths (do not make directories)   -v  be verbose/print version info" fullword ascii
    $s3  = "warning:  SetFileTime() for %s error %d" fullword ascii
    $s4  = "  -X  restore ACLs (-XX => use privileges)   -s  spaces in filenames => '_'" fullword ascii
    $s5  = "warning: CreateFile() error %d (set file times for %s)" fullword ascii
    $s6  = "                                             -M  pipe through \"more\" pager" fullword ascii
    $s7  = " EAs fail security check" fullword ascii
    $s8  = "EZPrint Version 1.0" fullword wide
    $s9  = "  MS-DOS file attributes (%02X hex):                  %s%s%s%s%s%s%s%s" fullword ascii
    $s10 = "unkn. #11 (PK reserved)" fullword ascii
    $s11 = "About EZPrint" fullword wide
    $s12 = "EZPrin Document" fullword wide
    $s13 = "     failed setting attrib/times for %lu dir entries" fullword ascii
    $s14 = "  minimum software version required to extract:     %u.%u" fullword ascii
    $s15 = "  file last modified on (UT extra field modtime):   %s %s" fullword ascii
    $s16 = "  version of encoding software:                     %u.%u" fullword ascii
    $s17 = "        %sand cannot find %s, period." fullword ascii
    $s18 = "EZPrint MFC Application" fullword wide
    $s19 = "EZPrint Application" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}