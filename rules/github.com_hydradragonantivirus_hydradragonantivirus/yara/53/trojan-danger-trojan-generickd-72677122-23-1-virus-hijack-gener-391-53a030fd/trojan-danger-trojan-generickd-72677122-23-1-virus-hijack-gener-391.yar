import "pe"
rule _Trojan_Danger_Trojan_GenericKD_72677122_23_1_Virus_Hijack_Gener_391 {
  meta:
    description = "datamaliciousorder - from files Trojan.Danger_Trojan.GenericKD.72677122_23_1.vir, Virus.Hijack_Generic.Dacic.76A3436A.A.F9386529.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "81a1b83662c9ae79b34e7a43726251449b399c0558d1b4e355ef9d0d007f8b99"
    hash2       = "8fbac7c6bea3cc850f82af6c7991a0bde7536fad0538d657f8772e3843e586f7"

  strings:
    $s1 = "file:\\\\C:\\sys.exe" fullword wide
    $s2 = " R  A & \"\\StubPath\", \"file:\\\\c:\\sys.exe\", \"REG_SZ\" " fullword ascii
    $s3 = "[Shutdown]" fullword wide
    $s4 = "\"GPOName\"=\"Local Group Policy\"" fullword ascii
    $s5 = "\"DisplayName\"=\"Local Group Policy\"" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "26d953f374008e1aeb3b4245c47084fa" and (all of them)
    ) or (all of them)
}