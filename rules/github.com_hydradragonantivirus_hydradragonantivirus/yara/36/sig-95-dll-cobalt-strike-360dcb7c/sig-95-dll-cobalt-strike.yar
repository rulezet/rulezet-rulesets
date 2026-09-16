import "pe"
rule sig_95_dll_cobalt_strike {
  meta:
    description = "file 95.dll"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com"
    date        = "2021-06-24"
    hash1       = "7b2144f2b5d722a1a8a0c47a43ecaf029b434bfb34a5cffe651fda2adf401131"

  strings:
    $s1  = "TstDll.dll" fullword ascii
    $s2  = "!This is a Windows NT windowed dynamic link library" fullword ascii
    $s3  = "AserSec" fullword ascii
    $s4  = "`.idata" fullword ascii  
    $s5  = "vEYd!W" fullword ascii
    $s6  = "[KpjrRdX&b" fullword ascii
    $s7  = "XXXXXXHHHHHHHHHHHHHHHHHHHH" fullword ascii  
    $s8  = "%$N8 2" fullword ascii
    $s9  = "%{~=vP" fullword ascii
    $s10 = "it~?KVT" fullword ascii
    $s11 = "UwaG+A" fullword ascii
    $s12 = "mj_.%/2" fullword ascii
    $s13 = "BnP#lyp" fullword ascii
    $s14 = "(N\"-%IB" fullword ascii
    $s15 = "KkL{xK" fullword ascii
    $s16 = ")[IyU," fullword ascii
    $s17 = "|+uo6\\" fullword ascii
    $s18 = "@s?.N^" fullword ascii
    $s19 = "R%jdzV" fullword ascii
    $s20 = "R!-q$Fl" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 100KB and
    (pe.imphash() == "67fdc237b514ec9fab9c4500917eb60f" and (pe.exports("AserSec") and pe.exports("TstSec")) or all of them)
}