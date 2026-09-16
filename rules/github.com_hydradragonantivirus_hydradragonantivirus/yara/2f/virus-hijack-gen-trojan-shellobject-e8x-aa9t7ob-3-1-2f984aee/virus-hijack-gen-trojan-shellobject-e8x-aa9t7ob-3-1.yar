rule Virus_Hijack_Gen_Trojan_ShellObject_e8X_aa9T7Ob_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.e8X@aa9T7Ob_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d6af47e7d8e6514ff5c9d0d58faed7c1b3dfa64251dd1db07c8b75e5adbcef3"

  strings:
    $x1  = "Two girls - Blonde and Brunette - Giving head.exe" fullword ascii
    $s2  = "jenna jameson - shower scene.exe" fullword ascii
    $s3  = "CKY3 - Bam Margera World Industries Alien Workshop.exe" fullword ascii
    $s4  = "password stealer.exe" fullword ascii
    $s5  = "AIM Password Stealer.exe" fullword ascii
    $s6  = "Windows 2000 win2k password stealer.exe" fullword ascii
    $s7  = "jenna jameson - built for speed.exe" fullword ascii
    $s8  = "hotmail account sniffer.exe" fullword ascii
    $s9  = "MSN Password Hacker and Stealer.exe" fullword ascii
    $s10 = "AOL, MSN, Yahoo mail password stealer.exe" fullword ascii
    $s11 = "aol password cracker.exe" fullword ascii
    $s12 = "Another bang bus victim forced rape sex cum.mpg.exe" fullword ascii
    $s13 = "cute girl giving head.exe" fullword ascii
    $s14 = "chubby girl fucked from all angles xxx.exe" fullword ascii
    $s15 = "windows xp key generator and cracker.exe" fullword ascii
    $s16 = "Counter Strike CD Keygen.exe" fullword ascii
    $s17 = "porn account cracker.exe" fullword ascii
    $s18 = "Microsoft Office XP (english) key generator.exe" fullword ascii
    $s19 = "AIM Account Stealer.exe" fullword ascii
    $s20 = "AIM Account Hacker.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}