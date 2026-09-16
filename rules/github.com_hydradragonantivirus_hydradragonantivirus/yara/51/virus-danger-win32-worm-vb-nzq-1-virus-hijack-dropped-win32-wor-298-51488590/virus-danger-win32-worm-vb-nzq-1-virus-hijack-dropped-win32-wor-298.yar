rule _Virus_Danger_Win32_Worm_VB_NZQ_1_Virus_Hijack_Dropped_Win32_Wor_298 {
  meta:
    description = "datamaliciousorder - from files Virus.Danger_Win32.Worm.VB.NZQ_1.vir, Virus.Hijack_Dropped.Win32.Worm.VB.NXJ.vir, Virus.Hijack_Dropped.Win32.Worm.VB.NXJ_1.vir, Virus.Hijack_Gen.Trojan.ShellObject.f8X@amgke!k_20_2.vir, Virus.Hooker_Trojan.GenericKD.64731121.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86501b6f1f138531408efabe39c58b5c8e5f00c20916a0aa803ab7578d2d8c9d"
    hash2       = "b4f34a5139502cad69b5c7d3138ff4d527894013f5a5471e176019ec675490bf"
    hash3       = "6eab816a4bcf7258e1b7ee52a7113aaa36abd6ad3ae7508c094aacf6cff19020"
    hash4       = "b00888b91be353d18e18c45d23c3967d666971a1f717bd02a9e9850292d73f39"
    hash5       = "9633d4cd7b4f96fbe5e897823eecfe25c6f8b221ac7606874f8112c0c5229127"

  strings:
    $x1  = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><dependency><dependentAssembly><assemblyIdentity ty" ascii
    $s2  = "This version of %s is not supported.  You should upgrade to Service Pack %s and run setup again.  Setup will now terminate." fullword wide
    $s3  = "This version of Internet Explorer is not supported.  You should upgrade Internet Explorer to version %s and run setup again.  Se" wide
    $s4  = "This operating system is not supported by this installation.  Setup will now terminate." fullword wide
    $s5  = "Download failed.  Error = 0x%08lX" fullword wide
    $s6  = "Setup needs to restart your system to complete the installation.  Do you want to restart now?" fullword wide
    $s7  = "Deze versie van %s wordt niet ondersteund. U moet opwaarderen naar Service Pack %s en de installatie opnieuw uitvoeren. Het inst" wide
    $s8  = "Denne version af %s underst" fullword wide
    $s9  = "Diese Version von %s wird nicht unterst" fullword wide
    $s10 = "Cette version de %s n'est pas prise en charge. Mettez-la " fullword wide
    $s11 = "MSI-Version %s ist erforderlich. Es steht jedoch kein Update zur Verf" fullword wide
    $s12 = "MSI version %s est requis, mais la mise " fullword wide
    $s13 = "Version %s av MSI kr" fullword wide
    $s14 = "Downloading MSI update, it may take a few minutes. Please wait." fullword wide
    $s15 = "sm.v3\"><ms_asmv3:security><ms_asmv3:requestedPrivileges>" fullword ascii
    $s16 = "Installationsprogrammet skal genstarte systemet for at afslutte installationen. Vil du genstarte nu?" fullword wide
    $s17 = "Setup  muss das System zum Beenden der Installation neu starten. Jetzt neu starten?" fullword wide
    $s18 = "De computer moet opnieuw worden opgestart om de installatie te voltooien. Wilt u de computer nu opnieuw opstarten?" fullword wide
    $s19 = "Dieses Betriebssystem wird von dieser Installation nicht unterst" fullword wide
    $s20 = "MSI-versie %s is vereist, maar er is geen update beschikbaar." fullword wide

  condition:
    (uint16(0) == 0x5a4d and (1 of ($x*) and 4 of them)
    ) or (all of them)
}