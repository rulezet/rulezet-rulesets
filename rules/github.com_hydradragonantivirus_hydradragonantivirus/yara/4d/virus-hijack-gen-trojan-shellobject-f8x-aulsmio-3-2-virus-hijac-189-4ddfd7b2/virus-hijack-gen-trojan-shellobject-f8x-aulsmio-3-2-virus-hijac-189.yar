rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_auLSMIo_3_2_Virus_Hijac_189 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@auLSMIo_3_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.fCY@aijlKSl_14_2.vir, Virus.Hijack_Trojan.GenericKDZ.105924_233_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9b6d8d4e5e6cd4b77e5a6c7210788216aa3bb117891716f5015552052351ce2"
    hash2       = "a5dfab92bc0fe88046376c003f550774217c4668c8d766ded7b45a5d3fd4eab0"
    hash3       = "30f2f4066055982aa217e1da873c8c5306b812730a14c821c3dca50fec8f4fef"

  strings:
    $s1  = "|6408|UI_STATS|FreeCell Statistics - %1//statistics dialog title (with username)" fullword wide
    $s2  = "FreeCellGame::doFakeClick() - %p (move pending=%d)" fullword wide
    $s3  = "Executable for FreeCell Game" fullword wide
    $s4  = "FreeCellGame::OnCardDragStarted() - Card should belong to stack named %s, not %s" fullword wide
    $s5  = "|6409|UI_STATS|FreeCell Statistics//statistics dialog title (no username)" fullword wide
    $s6  = "FreeCellStatistics::FromXml() - NULL source xml." fullword wide
    $s7  = "FreeCellStatistics::ToXml() - NULL parent tag." fullword wide
    $s8  = "FreeCellOptions::FromXml() - NULL source xml." fullword wide
    $s9  = "FreeCellOptions::ToXml() - NULL parent tag." fullword wide
    $s10 = "FreeCellGameState::FromXml() - NULL source xml." fullword wide
    $s11 = "FreeCellGameState::ToXml() - NULL parent tag." fullword wide
    $s12 = "Failed to get the freecell layout xml" fullword wide
    $s13 = "FreeCellGame::LoadGeneralData() - Unable to load the settings file %s" fullword wide
    $s14 = "FreeCellGame::LoadGeneralData() - Unable to load the stats in %s" fullword wide
    $s15 = "FreeCellGame::LoadGeneralData() - Unable to load the options in %s" fullword wide
    $s16 = "FreeCellGame::LoadStateData() - Unable to load the game state file %s" fullword wide
    $s17 = "FreeCellGame::LoadStateData() - Unable to load the game state in %s" fullword wide
    $s18 = "FreeCellGame::SaveGeneralData() - Unable to save the stats to %s" fullword wide
    $s19 = "FreeCellGame::SaveGeneralData() - Unable to save the options to %s" fullword wide
    $s20 = "FreeCellGame::SaveGeneralData() - Unable to save the settings to %s" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}