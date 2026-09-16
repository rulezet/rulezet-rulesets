import "pe"
rule quantum_p227 {
  meta:
    description = "Cobalt Strike - file p227.dll"
    author      = "The DFIR Report"
    reference   = "https://thedfirreport.com/2022/04/25/quantum-ransomware/"
    date        = "2022-04-24"
    hash1       = "c140ae0ae0d71c2ebaf956c92595560e8883a99a3f347dfab2a886a8fb00d4d3"

  strings:
    $s1  = "Remote Event Log Manager4" fullword wide
    $s2  = "IIdRemoteCMDServer" fullword ascii
    $s3  = "? ?6?B?`?" fullword ascii  
    $s4  = "<*=.=2=6=<=\\=" fullword ascii  
    $s5  = ">'?+?/?3?7?;???" fullword ascii  
    $s6  = ":#:':+:/:3:7:" fullword ascii  
    $s7  = "2(252<2[2" fullword ascii  
    $s8  = ":$;,;2;>;F;" fullword ascii  
    $s9  = ":<:D:H:L:P:T:X:\\:`:d:h:l:p:t:x:|:" fullword ascii
    $s10 = "%IdThreadMgr" fullword ascii
    $s11 = "AutoHotkeys<mC" fullword ascii
    $s12 = "KeyPreview0tC" fullword ascii
    $s13 = ":dmM:\\m" fullword ascii
    $s14 = "EFilerErrorH" fullword ascii
    $s15 = "EVariantBadVarTypeErrorL" fullword ascii
    $s16 = "IdThreadMgrDefault" fullword ascii
    $s17 = "Set Size Exceeded.*Error on call Winsock2 library function %s&Error on loading Winsock2 library (%s)" fullword wide
    $s18 = "CopyMode0" fullword ascii
    $s19 = "TGraphicsObject0" fullword ascii
    $s20 = "THintWindow8" fullword ascii

  condition:
    uint16(0) == 0x5a4d and filesize < 2000KB and
    (pe.imphash() == "c88d91896dd5b7d9cb3f912b90e9d0ed" or 8 of them)
}