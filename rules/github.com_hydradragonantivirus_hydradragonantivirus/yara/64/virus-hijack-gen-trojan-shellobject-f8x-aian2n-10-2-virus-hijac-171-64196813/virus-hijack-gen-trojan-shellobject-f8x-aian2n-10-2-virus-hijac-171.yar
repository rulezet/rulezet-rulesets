rule _Virus_Hijack_Gen_Trojan_ShellObject_f8X_aian2n_10_2_Virus_Hijac_171 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.f8X@aian2n_10_2.vir, Virus.Hijack_Gen.Trojan.ShellObject.h8X@a0kuefc_4_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1f73c852f46af89ba4d6ffa45263ad6de9327da6f3ffef7218213441bdfab73"
    hash2       = "59410b9fcb6dfbc62f5fa8a5bc2d7d98d992230a3b67585794aa57fde692f7e1"

  strings:
    $s1  = "Windows PowerShell Integrated Scripting Environment. Performs object-based (command-line) functions" fullword wide
    $s2  = "Connect to remote iSCSI targets and configure connection settings." fullword wide
    $s3  = "Change user account settings and passwords for people who share this computer." fullword wide
    $s4  = "Add new users to your computer" fullword wide
    $s5  = "Manage COM+ applications, COM and DCOM system configuration, and the Distributed Transaction Coordinator." fullword wide
    $s6  = "Choose when you want User Account Control (UAC) to notify you about changes to your computer." fullword wide
    $s7  = "View the desktop gadgets installed on your computer." fullword wide
    $s8  = "View HomeGroup settings, choose sharing options, and view or change the password." fullword wide
    $s9  = "Get information about your computer's speed and performance. If solutions to performance problems are available, Windows lets yo" wide
    $s10 = "Use a homegroup to share with other computers in your home" fullword wide
    $s11 = "Defragments your disks so that your computer runs faster and more efficiently." fullword wide
    $s12 = "Perform advanced troubleshooting and system configuration" fullword wide
    $s13 = "Backup and restore your files and system. Monitor latest backup status and configuration." fullword wide
    $s14 = "Share files and printers with other computers in your home." fullword wide
    $s15 = "Create user accounts for other people who will use this computer." fullword wide
    $s16 = "Restore your system to an earlier time without affecting your files, or replace everything on your computer and reinstall Window" wide
    $s17 = "Configure your Internet display and connection settings." fullword wide
    $s18 = "View information about your computer, and change settings for hardware, performance, and remote connections." fullword wide
    $s19 = "Go online to get Windows Live Essentials" fullword wide
    $s20 = "Desktop Gadget Gallery" fullword wide

  condition:
    (uint16(0) == 0x5a4d and (8 of them)
    ) or (all of them)
}