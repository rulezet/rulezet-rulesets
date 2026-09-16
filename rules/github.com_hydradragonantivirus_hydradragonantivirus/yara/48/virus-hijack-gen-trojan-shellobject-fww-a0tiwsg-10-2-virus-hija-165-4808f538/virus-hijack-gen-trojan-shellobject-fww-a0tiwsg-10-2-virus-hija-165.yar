import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_fWW_a0tiwSg_10_2_Virus_Hija_165 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.fWW@a0tiwSg_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.u8Z@aqsS8zj_12_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b35021f76bf0585b970e2be0716dae07652242bae8affb1ee54288b367312a8b"
    hash2       = "4e62e7a3b77d4d0abb803c175f51d1242fda33bfd3308991b9e90391cac1c369"

  strings:
    $s1  = "|56799|UI_STATS|Mahjong Titans Statistics - %1// statistics dialog title (with username)" fullword wide
    $s2  = "Executable for Mahjong Titans Game" fullword wide
    $s3  = "UISolitaireCanvas::UISolitaireCanvas() - Unable to get the layout button nodes" fullword wide
    $s4  = "UISolitaireCanvas::UISolitaireCanvas() - Unable to get the title nodes" fullword wide
    $s5  = "|44069|UI_STATS|Mahjong Titans Statistics// statistics dialog title (no username)" fullword wide
    $s6  = "<description>Mahjong Titans</description>" fullword ascii
    $s7  = "Failed to find a hint for game; is game already won?" fullword wide
    $s8  = "UISolitaireCanvas::UISolitaireCanvas() - Couldn't open XML" fullword wide
    $s9  = "Special Combo!" fullword wide
    $s10 = "Basic Combo!" fullword wide
    $s11 = "|59156|StatDialog|Win percentage: %1!d!%%" fullword wide
    $s12 = "Not enough high score fields in dialog" fullword wide
    $s13 = "|41049|WinLoseDialog|Congratulations! You won the game! " fullword wide
    $s14 = "|42369|WinLoseDialog|Game Lost" fullword wide
    $s15 = "|63423|WinLoseDialog|Sorry, you lost this game. Better luck next time! " fullword wide
    $s16 = "|64860|WinLoseDialog|High score: %1!d! " fullword wide
    $s17 = "|54443|WinLoseDialog|Win percentage: %1!d!%%" fullword wide
    $s18 = "UISolitaireCanvas::UISolitaireCanvas() - Unable to create the tip node" fullword wide
    $s19 = "Animation type not found [%d]" fullword wide
    $s20 = "Combo Multiplier: " fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "b941ddedcc51e5706d41335adb4e6b2a" and (8 of them)
    ) or (all of them)
}