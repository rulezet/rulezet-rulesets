rule _Trojan_Hooker_Win32_Floxif_A_33_1_Virus_Autorun_Generic_Dacic_3_376 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Win32.Floxif.A_33_1.vir, Virus.Autorun_Generic.Dacic.3DD73544.A.1D459A1C.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c9594b207d3fab009a7900e1031007d8e8122ad0b57956c9b000b53dcc487e7a"
    hash2       = "f1199c465067c2d9fa2a32a8dd6296a1b3c9af40ac3cfb37fc3b32b2bd13be19"

  strings:
    $s1  = "<EXECUTE>" fullword ascii
    $s2  = "##################### INFECTION PATH  #####################" fullword ascii
    $s3  = "##################### LAST TOKEN INFO #####################" fullword ascii
    $s4  = "##################### LAST KEY STROKE #####################" fullword ascii
    $s5  = "<SELECT>" fullword ascii
    $s6  = "<SNAPSHOT>" fullword ascii
    $s7  = "<RETURN>" fullword ascii
    $s8  = "<CONVERT>" fullword ascii
    $s9  = "<BACKSPACE>" fullword ascii
    $s10 = "<ACCEPT>" fullword ascii
    $s11 = "<NEXT>" fullword ascii
    $s12 = "<PRIOR>" fullword ascii
    $s13 = "<PAUSE>" fullword ascii
    $s14 = "<CLEAR>" fullword ascii
    $s15 = "<HOME>" fullword ascii
    $s16 = "<CANCEL>" fullword ascii
    $s17 = "View Webcam" fullword ascii
    $s18 = "<ESCAPE>" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}