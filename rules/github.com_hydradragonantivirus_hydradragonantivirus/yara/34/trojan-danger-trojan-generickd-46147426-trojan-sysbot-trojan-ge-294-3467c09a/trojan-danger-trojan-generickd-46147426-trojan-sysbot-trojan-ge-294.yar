rule _Trojan_Danger_Trojan_GenericKD_46147426_Trojan_Sysbot_Trojan_Ge_294 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.46147426.vir, Trojan.Sysbot_Trojan.GenericKD.46147426.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aiYvnz_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8Y@aSZtDuk_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fKX@aeBHSxm_12_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_16.vir, Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_1_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51cf85f0909adb4c6b6473126e86916877768b1a1233cca35c189529e226cb43"
    hash2       = "263456e9a50d7005b5ea1ff87ffaf00d0a2c70d1b6451b2b2d27edce3246667d"
    hash3       = "d0a2b6770506c34ba0fa1eddc6de658234f1de956ff7edc7d8c857ad6ca4d387"
    hash4       = "ae504670119ccd3e69bfc73504f8c75d9a4d1571ab6e8e280b9dd6569708f617"
    hash5       = "481661ee588977620bbae38616277f88fbe6796ccad47d65205a8d061ef43bb1"
    hash6       = "d9431bfa0b15c0664e6da4d8c617ce5d2b9dc9af0016c8be47246bcb74418c95"
    hash7       = "c35804a74edf23b99ba415d32b56dcd2dec5a0332ea141327e02895dc66e5872"
    hash8       = "89a1af3a2afece7e197443049ab929855cd0cd7fe16b60c37a8af1f4d76aa1db"
    hash9       = "fd83aebb760b453007012f15679db7dbcb0e7807ba8c348834b8193e6d9cb17a"

  strings:
    $s1  = "  <File Name=\"Root\\vfs\\programfilescommonx64\\microsoft shared\\vba\\vba7.1\\vbe7.dll\" />" fullword ascii
    $s2  = "  <File Name=\"Root\\vfs\\programfilescommonx64\\microsoft shared\\office15\\riched20.dll\" />" fullword ascii
    $s3  = "  <File Name=\"Root\\vfs\\programfilescommonx86\\microsoft shared\\office15\\mso.dll\" />" fullword ascii
    $s4  = "  <File Name=\"Root\\vfs\\programfilescommonx86\\microsoft shared\\office15\\msptls.dll\" />" fullword ascii
    $s5  = "  <File Name=\"Root\\vfs\\programfilescommonx86\\microsoft shared\\office15\\riched20.dll\" />" fullword ascii
    $s6  = "  <File Name=\"Root\\vfs\\programfilescommonx86\\microsoft shared\\office15\\1033\\msointl.dll\" />" fullword ascii
    $s7  = "  <File Name=\"Root\\vfs\\programfilescommonx64\\microsoft shared\\office15\\msores.dll\" />" fullword ascii
    $s8  = "  <File Name=\"Root\\vfs\\programfilescommonx86\\microsoft shared\\vba\\vba7.1\\vbe7.dll\" />" fullword ascii
    $s9  = "  <File Name=\"Root\\vfs\\programfilescommonx64\\microsoft shared\\office15\\1033\\msointl.dll\" />" fullword ascii
    $s10 = "  <File Name=\"Root\\vfs\\programfilescommonx86\\microsoft shared\\office15\\msores.dll\" />" fullword ascii
    $s11 = "  <File Name=\"Root\\vfs\\programfilescommonx86\\microsoft shared\\office15\\1033\\xlsrvintl.dll\" />" fullword ascii
    $s12 = "  <File Name=\"Root\\vfs\\programfilescommonx86\\microsoft shared\\vba\\vba7.1\\vbeui.dll\" />" fullword ascii
    $s13 = "  <File Name=\"Root\\vfs\\programfilescommonx64\\microsoft shared\\office15\\1033\\xlsrvintl.dll\" />" fullword ascii
    $s14 = "  <File Name=\"Root\\vfs\\programfilescommonx64\\microsoft shared\\vba\\vba7.1\\vbeui.dll\" />" fullword ascii
    $s15 = "  <File Name=\"Root\\vfs\\programfilescommonx64\\microsoft shared\\office15\\mso.dll\" />" fullword ascii
    $s16 = "  <File Name=\"Root\\vfs\\programfilescommonx64\\microsoft shared\\office15\\msptls.dll\" />" fullword ascii
    $s17 = "  <File Name=\"Root\\vfs\\system\\msvcr100.dll\" />" fullword ascii
    $s18 = "  <File Name=\"Root\\office15\\addins\\umoutlookaddin.dll\" />" fullword ascii
    $s19 = "  <File Name=\"Root\\office15\\1033\\ppintl.dll\" />" fullword ascii
    $s20 = "  <File Name=\"Root\\office15\\1033\\xlintl32.dll\" />" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}