rule Virus_Autorun_Win32_Neshta_A_51 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Win32.Neshta.A_51.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "16735b30bd6e9ebe895e89f9c47930d2ec830da08d61f73129a6bf0213bed4dd"

  strings:
    $x1  = "user.config{0}\\FileZilla\\sitemanager.xmlcookies.sqlite\\Program Files (x86)\\configRoninWalletdisplayNamehost_key\\Electrum\\w" wide
    $s2  = "BCrypt.BCryptGetProperty() (get size) failed with status code:{0}" fullword wide
    $s3  = "BCrypt.BCryptGetProperty() failed with status code:{0}" fullword wide
    $s4  = "BCrypt.BCryptImportKey() failed with status code:{0}" fullword wide
    $s5  = "<Scan>b__0_6" fullword ascii
    $s6  = "<Scan>b__3" fullword ascii
    $s7  = "<Scan>b__0_2" fullword ascii
    $s8  = "<Scan>b__0_8" fullword ascii
    $s9  = "<Scan>b__0_4" fullword ascii
    $s10 = "<Scan>b__0_0" fullword ascii
    $s11 = "<Hardware>k__BackingField" fullword ascii
    $s12 = "<Proton>k__BackingField" fullword ascii
    $s13 = "*wallet*" fullword wide
    $s14 = "Armory" fullword wide
    $s15 = "Wombat" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    1 of ($x*) and 4 of them
}