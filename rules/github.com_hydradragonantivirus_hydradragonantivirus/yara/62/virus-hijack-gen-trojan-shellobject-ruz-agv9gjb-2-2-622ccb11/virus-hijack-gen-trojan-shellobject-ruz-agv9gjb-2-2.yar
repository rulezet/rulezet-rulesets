rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_2_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_2_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dd3ec8217dec2753a0fe63e3be2c6cb43cb719b7e19c035d811ca46d636bb55f"

  strings:
    $s1  = "If you value QuickSFV and wish to show your appreciation, please visit Kagi.com or PayPal.com and make a contribution to quicksf" wide
    $s2  = "%s: %08x:  %s (Previously verified)" fullword ascii
    $s3  = "%s: %s:  %s (Previously verified)" fullword ascii
    $s4  = " (File:%u%%)" fullword ascii
    $s5  = "Could not open output file: \"%s\"" fullword ascii
    $s6  = "Invalid line in CSV file: \"%s\"" fullword ascii
    $s7  = "Invalid .CKZ format" fullword ascii
    $s8  = "%d filename%s resolved to multiple filenames and %s not verified" fullword ascii
    $s9  = "Invalid line in SFV file: \"%s\"" fullword ascii
    $s10 = "There %s %d bad file%s and %d missing file%s" fullword ascii
    $s11 = "Invalid line in CKZ file: \"%s\"" fullword ascii
    $s12 = "No name specified for new .sfv file" fullword ascii
    $s13 = "There %s %d bad file%s" fullword ascii
    $s14 = "Could not open file: \"%s\"" fullword ascii
    $s15 = "There %s %d missing file%s" fullword ascii
    $s16 = "Sheriff" fullword ascii
    $s17 = " Copyright 1999-2004, Totally Useful Software, Inc." fullword wide
    $s18 = "%s: :   Invalid .PAR file" fullword ascii
    $s19 = "Mo&ve all files to child directory" fullword ascii
    $s20 = "File length mismatch" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}