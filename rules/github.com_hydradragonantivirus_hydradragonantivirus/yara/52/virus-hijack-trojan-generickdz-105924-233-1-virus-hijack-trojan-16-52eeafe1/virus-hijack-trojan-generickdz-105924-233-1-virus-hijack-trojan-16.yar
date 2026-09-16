import "pe"
rule _Virus_Hijack_Trojan_GenericKDZ_105924_233_1_Virus_Hijack_Trojan_16 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.GenericKDZ.105924_233_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_235_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30f2f4066055982aa217e1da873c8c5306b812730a14c821c3dca50fec8f4fef"
    hash2       = "aa2256999cc65afcba5d973b00acb1764275d2b797488387d5af52b972889f81"
    hash3       = "6dcb20428ef096b85384de6f0fdea3d77a5552c3c7b8edde8875357bef236f89"

  strings:
    $s1  = "URL:DbgEng.dll Remoting Protocol" fullword ascii
    $s2  = "User-selected command window line text" fullword ascii
    $s3  = "User-selected command window line background" fullword ascii
    $s4  = "User-added command window text background" fullword ascii
    $s5  = "Error level command window text" fullword ascii
    $s6  = "User-added command window text" fullword ascii
    $s7  = "Error level command window text background" fullword ascii
    $s8  = "     <Ctrl-R><Enter> Resynchronize target and host" fullword ascii
    $s9  = "        Specifies the type of BUS the kernel debugger will use to communicate with the target" fullword ascii
    $s10 = "Internal event level command window text" fullword ascii
    $s11 = "Internal remoting level command window text background" fullword ascii
    $s12 = "Normal level command window text" fullword ascii
    $s13 = "Internal KD protocol level command window text" fullword ascii
    $s14 = "Internal breakpoint level command window text" fullword ascii
    $s15 = "Verbose level command window text background" fullword ascii
    $s16 = "Internal KD protocol level command window text background" fullword ascii
    $s17 = "Extension warning level command window text" fullword ascii
    $s18 = "Warning level command window text background" fullword ascii
    $s19 = "Prompt level command window text background" fullword ascii
    $s20 = "Debuggee prompt level command window text" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "c4998075f1324ce0f644f12a548d76b1" and (8 of them)
    ) or (all of them)
}