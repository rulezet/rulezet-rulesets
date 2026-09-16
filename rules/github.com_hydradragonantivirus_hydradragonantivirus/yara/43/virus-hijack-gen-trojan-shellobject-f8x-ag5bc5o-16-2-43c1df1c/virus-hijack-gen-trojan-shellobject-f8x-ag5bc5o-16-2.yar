rule Virus_Hijack_Gen_Trojan_ShellObject_f8X_aG5Bc5o_16_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8X@aG5Bc5o_16_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7022e9eaae48c6cd99709ff89823dcfd370ffc05c20db169c50b6aa59c404a3"

  strings:
    $s1  = "WEB SITE: http://www.nakka.com/" fullword wide
    $s2  = "dCLCL - Error" fullword wide
    $s3  = "\\ / : , ; * ? \" < > |UA folder with the name you specified already exists. Specify a different folder name." fullword wide
    $s4  = "Add to Template" fullword wide
    $s5  = "Failed in the hotkey register." fullword wide
    $s6  = "2Please select a folder to which you can add items.0Please select a folder to which copies Template./Please select a folder to w" wide
    $s7  = "PRIVATE LAST" fullword wide
    $s8  = "PRIVATE FIRST" fullword wide
    $s9  = "PRIVATE ENHANCED METAFILE" fullword wide
    $s10 = "PRIVATE METAFILE PICTURE" fullword wide
    $s11 = "PRIVATE BITMAP" fullword wide
    $s12 = "PRIVATE TEXT" fullword wide
    $s13 = "-Failed in save." fullword wide
    $s14 = "!Please select a folder to export." fullword wide
    $s15 = "DROP FILE LIST" fullword wide
    $s16 = "&Add to Template..." fullword wide
    $s17 = "Add to &Template..." fullword wide
    $s18 = "GDI OBJECT LAST" fullword wide
    $s19 = "GDI OBJECT FIRST" fullword wide
    $s20 = "OWNER DISPLAY" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    8 of them
}