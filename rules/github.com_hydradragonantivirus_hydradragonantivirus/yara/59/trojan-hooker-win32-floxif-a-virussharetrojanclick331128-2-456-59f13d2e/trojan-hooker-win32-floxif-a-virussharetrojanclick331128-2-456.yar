rule _Trojan_Hooker_Win32_Floxif_A_VirusShareTrojanClick331128_2_456 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Win32.Floxif.A.vir, VirusShareTrojanClick331128_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7d18bec8c65d9f6752dcd4406d77919e1148c93b1e3258d30d6425cc9cbcffe"
    hash2       = "83e96f918c41f027a280a1da16c6cd31694be1dda694851e13752ea8c2be3e11"

  strings:
    $s1 = "s Pty Limited <www.di-mgt.com.au>, and is used with permission." fullword ascii
    $s2 = "Contains multiple-precision arithmetic code originally written by David Ireland, copyright (c) 2001-6 by D.I. Management Service" ascii
    $s3 = ". Possibility in image path: " fullword ascii
    $s4 = ". Possibility in current path: " fullword ascii
    $s5 = "Avira Product Family" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}