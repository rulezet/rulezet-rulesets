import "pe"
rule _Virus_Hijack_Trojan_GenericKDZ_105924_275_1_Virus_Hijack_Trojan_369 {
  meta:
    description = "datamaliciousorder - from files Virus.Hijack_Trojan.GenericKDZ.105924_275_1.vir, Virus.Hijack_Trojan.GenericKDZ.105924_276_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ac7aef0bfd865d690df973fcae886b4b5601646061b3ed283dc123393905ce73"
    hash2       = "0f3d7aaa2ab0126a98d42def968516d2d10b5e1570c534a7e9c55de2a5e8bc77"

  strings:
    $s1 = "Select * From " fullword ascii
    $s2 = ";User ID=" fullword ascii
    $s3 = ";Persist Security Info=True;Initial Catalog=" fullword ascii
    $s4 = ";Data Source=" fullword ascii
    $s5 = "z>Item" fullword ascii

  condition:
    (uint16(0) == 0x5a4d and pe.imphash() == "961ee039a4809701ba009e6a9263b2b0" and (all of them)
    ) or (all of them)
}