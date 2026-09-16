import "pe"
rule _Virus_Hijack_Gen_Trojan_ShellObject_NvZ_aOnotPj_Virus_Hijack_Tr_166 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Gen.Trojan.ShellObject.NvZ@aOnotPj.vir, Virus.Hijack_Trojan.Agent.DQQO_50.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dd6cef8efe1855ae786a5f8420cd8dcf8884eabcedffbfaa723eff340e82d3c"
    hash2       = "5a4e2c5e991b9e68dff9539f16c2aabbc8721a658b1765448364254278dc9b79"

  strings:
    $s1  = "Failed to initialize not_on_ui_thread continuation context" fullword ascii
    $s2  = "Platform.?$WriteOnlyArray@P$AAVBindableFloatParam@ViewModel@PaintStudio@@$00" fullword wide
    $s3  = "Uncaught exception whilst attempting to silently sign in" fullword wide
    $s4  = "Platform.?$WriteOnlyArray@P$AAVKeyMapping@ViewModel@PaintStudio@@$00" fullword wide
    $s5  = "Extrusion Type" fullword wide
    $s6  = "TextTool VM (rotating)" fullword wide
    $s7  = "Platform.?$WriteOnlyArray@P$AAVUri@Foundation@Windows@@$00" fullword wide
    $s8  = "Platform.?$WriteOnlyArray@P$AAVColorViewModel@ViewModel@PaintStudio@@$00" fullword wide
    $s9  = "Platform.?$WriteOnlyArray@P$AAUIToolBoxBlock@ViewModel@PaintStudio@@$00" fullword wide
    $s10 = "Learn and Feedback" fullword wide
    $s11 = "Platform.?$WriteOnlyArray@P$AAVMenuItem@ViewModel@PaintStudio@@$00" fullword wide

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "26babd76bbb7f9c516a338b0601b4c9f" and (8 of them)
    ) or (all of them)
}