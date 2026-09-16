import "pe"
rule cobalt_strike_14435_dll_1 {
  meta:
    description = "1.dll"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2022-09-12"
    hash1       = "1b9c9e4ed6dab822b36e3716b1e8f046e92546554dff9bdbd18c822e18ab226b"

  strings:
    $s1  = "curity><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"></requestedExecutionLevel></requeste" ascii
    $s2  = "CDNS Project.dll" fullword ascii
    $s3  = "hemas.microsoft.com/SMI/2005/WindowsSettings\">true</dpiAware></windowsSettings></application></assembly>" fullword ascii
    $s4  = "Hostname to lookup:" fullword wide
    $s5  = "Hostnames:" fullword wide
    $s6  = "wOshV- D3\"RIcP@DN \\" fullword ascii
    $s7  = "T4jk{zrvG#@KRO* d'z" fullword ascii
    $s8  = "CDNS Project Version 1.0" fullword wide
    $s9  = "zK$%S.cPO>rtW" fullword ascii
    $s10 = "vOsh.HSDiXRI" fullword ascii
    $s11 = "l4p.oZewOsh7zP" fullword ascii
    $s12 = "5p2o.ewOsh7H" fullword ascii
    $s13 = "h7H.DiX" fullword ascii
    $s14 = "l4pWo.ewOsh[H%DiXRI" fullword ascii
    $s15 = "rEWS).lpp~o" fullword ascii
    $s16 = ",m}_lOG" fullword ascii
    $s17 = "<assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3" ascii
    $s18 = "vileges></security></trustInfo><application xmlns=\"urn:schemas-microsoft-com:asm.v3\"><windowsSettings><dpiAware xmlns=\"http:/" ascii
    $s19 = "tn9- 2" fullword ascii
    $s20 = "PDiXRI7" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 8000KB and
    (pe.imphash() == "d1aef4e37a548a43a95d44bd2f8c0afc" or 8 of them)
}