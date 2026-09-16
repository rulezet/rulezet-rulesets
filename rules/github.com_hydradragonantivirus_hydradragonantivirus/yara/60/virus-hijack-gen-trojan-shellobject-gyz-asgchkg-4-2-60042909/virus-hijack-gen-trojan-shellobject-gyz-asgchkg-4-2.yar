rule Virus_Hijack_Gen_Trojan_ShellObject_gyZ_aSgChKg_4_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.gyZ@aSgChKg_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b1937825f1f7517dada428aee72f3f8387f43358cede8409a6589dafe6b7ece"

  strings:
    $x1  = "Star Wars Episode 2 - Attack Of The Clones Full Downloader.exe" fullword ascii
    $x2  = "Sony Play station boot disc - Downloader.exe" fullword ascii
    $x3  = "CKY3 - Bam Margera World Industries Alien Workshop Full Downloader.exe" fullword ascii
    $x4  = "Jenna Jameson - Built For Speed Downloader.exe" fullword ascii
    $x5  = "AIM Account Stealer Downloader.exe" fullword ascii
    $x6  = "Windows XP Full Downloader.exe" fullword ascii
    $x7  = "Gladiator FullDownloader.exe" fullword ascii
    $x8  = "[DiVX] Harry Potter And The Sorcerors Stone Full Downloader.exe" fullword ascii
    $x9  = "[DiVX] Lord of The Rings Full Downloader.exe" fullword ascii
    $x10 = "Star wars episode 2 downloader.exe" fullword ascii
    $x11 = "Macromedia Flash 5.0 Full Downloader.exe" fullword ascii
    $x12 = "ZoneAlarm Firewall Full Downloader.exe" fullword ascii
    $s13 = "ScaryMovie 2 Full Downloader.exe" fullword ascii
    $s14 = "Cat Attacks Child Full Downloader.exe" fullword ascii
    $s15 = "PS1 Boot Disc Full Dwonloader.exe" fullword ascii
    $s16 = "MSN Password Hacker and Stealer.exe" fullword ascii
    $s17 = "Battle.net key generator (WORKS!!).exe" fullword ascii
    $s18 = "Key generator for all windows XP versions.exe" fullword ascii
    $s19 = "Internet and Computer Speed Booster.exe" fullword ascii
    $s20 = "Macromedia key generator (all products).exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and all of them
}