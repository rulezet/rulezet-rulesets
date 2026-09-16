rule Virus_Hijack_GenPack_Backdoor_Hangup_B_49_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_49_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a7071927e998de5fe8c3a796faa1dbbedf0f4ffeafec6004250b3f202ecdd78"

  strings:
    $s1  = "  /C        Dump logging output to attached Console (Windows XP and above)." fullword wide
    $s2  = "Running on %s, 'Add/Remove Programs' is not supported and has been disabled." fullword wide
    $s3  = "            Wizard and any dialogs popped-up by the operating system." fullword wide
    $s4  = "Could not get INF PATH property for driver package \"%ws\"." fullword wide
    $s5  = "  /SW       Suppresses the Device Installation Wizard, the operating system" fullword wide
    $s6  = "Failed to delete 'Add or Remove Programs' entry %s." fullword wide
    $s7  = "Access denied! Administrator account required to install driver packages." fullword wide
    $s8  = "DRIVER_PACKAGE_REPAIR flag set but not supported on Longhorn. Flag will be ignored." fullword wide
    $s9  = "DRIVER_PACKAGE_LEGACY_MODE flag set but not supported on Longhorn. Flag will be ignored." fullword wide
    $s10 = "Access denied! Administrator account is required to uninstall driver packages." fullword wide
    $s11 = "Error encountered while adding reference of installer %ws to driver store %ws" fullword wide
    $s12 = "Access denied! Administrator account is required to install driver packages." fullword wide
    $s13 = "Error occurred while uninstalling driver package %ws" fullword wide
    $s14 = "DRIVER_PACKAGE_DELETE_FILES flag set but not supported on Longhorn. Flag will be ignored." fullword wide
    $s15 = "[/LogTitle Title]" fullword wide
    $s16 = "Can't read requested language 0x%X elements from Descriptor (DPInst.xml) because not present." fullword wide
    $s17 = "  /PATH Path" fullword wide
    $s18 = "  /U path to INF file" fullword wide
    $s19 = "            might still pop-up user dialogs." fullword wide
    $s20 = "all driver packages found." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}