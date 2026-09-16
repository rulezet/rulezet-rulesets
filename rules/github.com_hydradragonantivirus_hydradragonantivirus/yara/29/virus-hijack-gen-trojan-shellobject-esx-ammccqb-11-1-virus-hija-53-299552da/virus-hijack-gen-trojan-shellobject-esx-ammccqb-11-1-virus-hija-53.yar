import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_eSX_amMcCQb_11_1_Virus_Hija_53 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.eSX@amMcCQb_11_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.uGZ@ayM4QWg_5_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7419ec9a81b3efb3a3cf2eaba1f71cc275e339db58e86423000c79d0aa0fa277"
    hash2       = "88ccd59e3eade1dc55a06d47d019588ee825a5fe6d7ba193c29137fb1b632142"

  strings:
    $s1  = "Target Training Passed" fullword wide
    $s2  = "Hit Fuel Targets\"Remote Attack Bumper Hits" fullword wide
    $s3  = "Drop Target Hits" fullword wide
    $s4  = "Drop Targets" fullword wide
    $s5  = "Confirm=WAVEMIX.INF is missing - it must be in the pinball directory!" fullword wide
    $s6  = "Spot Target Hits" fullword wide
    $s7  = "Lt Commander" fullword wide
    $s8  = "About 3D Pinball%Hit Mission Targets To Select Mission" fullword wide
    $s9  = "Target Practice" fullword wide
    $s10 = "Stray Comet" fullword wide
    $s11 = "pinball.chm$Not enough memory to run 3D Pinball." fullword wide
    $s12 = "Warning -- Low Fuel" fullword wide
    $s13 = "Comet Destroyed" fullword wide
    $s14 = "80386 Required$3D Pinball for Windows - Space CadetqOne or more of the player controls is set to the same key," fullword wide
    $s15 = "Time Warp Forward" fullword wide
    $s16 = "Center Post" fullword wide
    $s17 = "Commodore" fullword wide
    $s18 = "Level One Commendation" fullword wide
    $s19 = "Level Two Commendation" fullword wide
    $s20 = "Level Three Commendation" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "9973fdd4b86d866b3faa39fa66cf7e0a" and (8 of them)
    ) or (all of them)
}