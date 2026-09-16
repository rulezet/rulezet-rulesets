rule Virus_Hijack_Gen_Trojan_ShellObject_ruZ_aGV9gJb_17 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.ruZ@aGV9gJb_17.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4c561ece13e2c251a55395898bf3d743c44d133ce8615e9a472649c7f9e995c0"

  strings:
    $s1  = "Copyright (C) 2018-2023 WK78.COM." fullword wide
    $s2  = "    <!-- DPI Aware -->" fullword ascii
    $s3  = "    <!-- Windows 6.0 Style -->  " fullword ascii
    $s4  = "    <!-- Administrator -->  " fullword ascii
    $s5  = " --snapshot" fullword wide
    $s6  = "WIM compression level" fullword wide
    $s7  = "About CoolBackup" fullword wide
    $s8  = " --solid" fullword wide
    $s9  = "\" --check" fullword wide
    $s10 = "Donate Link" fullword ascii
    $s11 = "Append Backup" fullword ascii
    $s12 = "Please select the partition to back up" fullword ascii
    $s13 = "Auto Shutdown" fullword ascii
    $s14 = "AlignMent" fullword ascii
    $s15 = "Archiving file data:" fullword wide
    $s16 = "PE environment help is not available." fullword wide
    $s17 = "PE environment is not available." fullword wide
    $s18 = "String(0)" fullword wide
    $s19 = "String(" fullword wide
    $s20 = "Error calling browser!" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}