rule _Trojan_Hooker_Win32_Floxif_A_18_Trojan_Hooker_Win32_Floxif_A_28_412 {
  meta:
    description = "datamaliciousorder - from files Trojan.Hooker_Win32.Floxif.A_18.vir, Trojan.Hooker_Win32.Floxif.A_28.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4e94cb903a2d465d27436e5f991f7c5e7ae30006b354b55b5f3b8ab8bb4208b"
    hash2       = "d90b5522b79ff27f5a4a1dd382f70e8afcb7ff94bcd79fa65b0714b4b5d1284d"

  strings:
    $s1 = "Record not found%Operation not allowed in a DBCtrlGrid(Property already defined by lookup field/Grid requested to display more t" wide
    $s2 = "USER NAME=host" fullword ascii
    $s3 = "OPEN MODE=READ/WRITE" fullword ascii
    $s4 = "ENABLE BCD=FALSE" fullword ascii
    $s5 = "BATCH COUNT=200" fullword ascii
    $s6 = "SCHEMA CACHE DIR=" fullword ascii
    $s7 = "ENABLE SCHEMA CACHE=FALSE" fullword ascii
    $s8 = "SCHEMA CACHE SIZE=8" fullword ascii
    $s9 = "SCHEMA CACHE TIME=-1" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}