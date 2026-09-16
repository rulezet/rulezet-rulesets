import "pe"
rule _Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_194_2_Tro_211 {
  meta:
    description = "datamaliciousorder - from files Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_194_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_196_2.vir, Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_199_2.vir, Virus.Delself_Trojan.GenericKD.38632388.vir, Virus.Delself_Trojan.GenericKD.38632388_1.vir, Virus.Hijack_Gen.Heur.Mint.Zard.30_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dbb267b95e6f1c3639bb267d347d05a8bcf99f5b835fe605b1e86a7e7b3f857b"
    hash2       = "a49d5ee298caf7ee053ed46a206f8d8aa1abf3acfe61719798c0cf338f6a3c4f"
    hash3       = "4511810343ffe65473d950c6638c0d4e9237e7bf84d843e2c3e856bcc9cd5443"
    hash4       = "b70b8824ee319ffd7bd1c6e5ac319a3cb45f36dbb7eb5ea4d9a7a8c7b11df773"
    hash5       = "647a1b3c87218ae8531de8f198ad56c5e39b91093353bbc58f69d8086d5bfc1e"
    hash6       = "67866b2cc2c65627481090fda91056657f994fbd21ecd4e9ad258235ddd2a3ae"

  strings:
    $s1  = "error resume nex" fullword ascii
    $s2  = ":F SYSTEM?" fullword ascii
    $s3  = "unning with" fullword ascii
    $s4  = "corN!g" fullword ascii
    $s5  = "Read{ " fullword ascii
    $s6  = "LANGUAGE 4," fullword ascii
    $s7  = "name,flag,Wsh" fullword ascii
    $s8  = " deflate 1.1.3 Co" fullword ascii
    $s9  = "ry=\"#BOUNDARY#" fullword ascii
    $s10 = "define _AFX_NO_SPLITTER_RESOURCE" fullword ascii
    $s11 = "Too many link@" fullword ascii
    $s12 = "path w" fullword ascii
    $s13 = "Ogress" fullword ascii
    $s14 = "gamma value " fullword ascii
    $s15 = "..Microelectronics Corp" fullword ascii
    $s16 = "d!Vista" fullword ascii
    $s17 = "known]" fullword ascii
    $s18 = "\"}Haul" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "1e31f5c802376e4482c519ed7f18135d" and (8 of them)
    ) or (all of them)
}