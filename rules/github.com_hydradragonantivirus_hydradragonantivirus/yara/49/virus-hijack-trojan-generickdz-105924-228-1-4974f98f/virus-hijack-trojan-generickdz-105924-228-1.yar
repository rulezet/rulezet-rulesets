rule Virus_Hijack_Trojan_GenericKDZ_105924_228_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_228_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d249b7e5475bd3265fac05ce313427ead0b0bcfef6bfae250b11ce57c475729a"

  strings:
    $s1 = "exceeded maximum command-line args %d" fullword wide
    $s2 = "%s : fatal error -: " fullword wide
    $s3 = "  -t, --tabs=LIST     use comma separated list of explicit tab positions" fullword ascii
    $s4 = "%1 is an unimplemented method" fullword wide
    $s5 = ",!3A,Rich 3A," fullword ascii
    $s6 = "  -i, --initial       do not convert tabs after non blanks" fullword ascii
    $s7 = "  -t, --tabs=NUMBER   have tabs NUMBER characters apart, not 8" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}