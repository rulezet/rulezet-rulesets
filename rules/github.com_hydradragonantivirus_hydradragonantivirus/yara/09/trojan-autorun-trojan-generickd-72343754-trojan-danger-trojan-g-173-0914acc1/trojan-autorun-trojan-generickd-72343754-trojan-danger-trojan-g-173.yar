import "pe"
rule _Trojan_Autorun_Trojan_GenericKD_72343754_Trojan_Danger_Trojan_G_173 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Trojan.GenericKD.72343754.vir, Trojan.Danger_Trojan.GenericKD.72853156_297_1.vir, Trojan.Danger_Trojan.GenericKD.72853156_387_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "306377c88666cfb50bed7e5ae5e81bb5a2e24b3cc0446686415e873ed1bf3898"
    hash2       = "8e9e3427f9d52a7a67fbd3a61b4ee365ea8028bf8731157e3563106a7108057f"
    hash3       = "69309a8a2810237bb81133630fe36264e6358ae1608085c7fb7915a049dd7b28"

  strings:
    $s1  = "d Company" fullword ascii
    $s2  = "colour s, -" fullword ascii
    $s3  = " number is %d. Q" fullword ascii
    $s4  = "complete)" fullword ascii
    $s5  = " XMP Core 4.1-c036 46.276720, M`" fullword ascii
    $s6  = "Tool>p32Snapshot" fullword ascii
    $s7  = "Output]S" fullword ascii
    $s8  = "<BODY  oncon" fullword ascii
    $s9  = "width:100%\"height?" fullword ascii
    $s10 = "textmenu='return false'" fullword ascii
    $s11 = "Write#`7" fullword ascii
    $s12 = ",Reference Vein" fullword ascii
    $s13 = "NWorld,form" fullword ascii
    $s14 = "Adobe P" fullword wide
    $s15 = "Patter" fullword ascii
    $s16 = "Timer'" fullword ascii
    $s17 = ";Radio" fullword ascii
    $s18 = "M.e]Origin" fullword ascii
    $s19 = "+08:00U*Modify" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "39a774befcd1acb895cf30a7ff631743" and (8 of them)
    ) or (all of them)
}