rule Trojan_Hooker_Win32_Floxif_A_4 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_4.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffe5ebeaa7a3ca11dc0a77f74968d94ca4e19be1e32413a7c32e3231e23c1ade"

  strings:
    $s1  = "method IccLibGetInfo - returns number of supported clocks and ICC Library versionWD" fullword ascii
    $s2  = "method IccLibGetClockId - returns IDs of clocks with specified usageWW@" fullword ascii
    $s3  = "method IccLibGetBootClockSettingsInvalidationReason - returns the boot time settings invalidation reason if apply failedWW," fullword ascii
    $s4  = "Intel(R) ICCS - setting per service SID failed " fullword wide
    $s5  = "method IccLibGetNextFrequency - returns the nearest higher frequencyWWG" fullword ascii
    $s6  = "method IccLibGetDefaultBootSettings - returns default boot settings for specified clockWWWZ" fullword ascii
    $s7  = "method IccLibGetPreviousFrequency - returns the nearest lower frequencyWWWx" fullword ascii
    $s8  = "method IccLibGetClockRanges - returns ranges for specified clockWWR" fullword ascii
    $s9  = "method IccLibGetCurrentClockSettings - return current settings for specified clockS" fullword ascii
    $s10 = "method IccLibGetBootClockSettings - returns boot time settings for specified clockC" fullword ascii
    $s11 = "method IccLibUseFwSim - sets the FW Simulator usage modeWW4" fullword ascii
    $s12 = "Intel(R) Integrated Clock Controller Service - Intel(R) ICCS" fullword wide
    $s13 = "method IccLibSetCurrentClockSettings - changes runtime settings for specified clockWWWR" fullword ascii
    $s14 = "method IccLibUseRealFw - stops the FW Simulator modeWW" fullword ascii
    $s15 = "method IccLibResetClockBootSettingsToDefaults - restores boot settings for specified clocka" fullword ascii
    $s16 = "method IccLibResetAllClocksBootSettingsToDefaults - restores default boot settings for all clocksWD" fullword ascii
    $s17 = "method IccLibSetBootClockSetting - changes boot time clock settingsWWWW" fullword ascii
    $s18 = "ICCProxy 1.0 Type LibraryW " fullword ascii
    $s19 = "Failed to send message request" fullword ascii
    $s20 = "Created by MIDL version 7.00.0500 at Tue Apr 24 13:46:14 2012" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}