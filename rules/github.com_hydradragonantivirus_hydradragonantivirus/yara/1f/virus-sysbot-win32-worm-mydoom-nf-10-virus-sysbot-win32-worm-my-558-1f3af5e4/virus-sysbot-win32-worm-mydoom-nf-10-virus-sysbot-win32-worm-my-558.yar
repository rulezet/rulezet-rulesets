rule _Virus_Sysbot_Win32_Worm_MyDoom_NF_10_Virus_Sysbot_Win32_Worm_My_558 {
  meta:
    description = "datamaliciousorder - from files Virus.Sysbot_Win32.Worm.MyDoom.NF_10.vir, Virus.Sysbot_Win32.Worm.MyDoom.NF_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f2fc1942458a86eae38b656110690832bc0726199f29d0d548b4f8b2bcd3a248"
    hash2       = "ef9b184878825bf94051286cc0d63f4ffe97a16d3b091fca88ad631bc8b86a74"

  strings:
    $s1 = "Cant find riched20.dll" fullword ascii
    $s2 = "&micro RichEdit" fullword ascii
    $s3 = "File changed. Save?" fullword ascii
    $s4 = "Copyright MASM32 2001" fullword ascii
    $s5 = "Cant open file" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (all of them)
    ) or (all of them)
}