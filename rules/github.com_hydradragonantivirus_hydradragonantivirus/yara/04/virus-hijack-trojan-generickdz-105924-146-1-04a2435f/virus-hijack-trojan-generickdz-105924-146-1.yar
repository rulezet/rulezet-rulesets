rule Virus_Hijack_Trojan_GenericKDZ_105924_146_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_146_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93acb9535c462ac183f0210a512a912040e4704d73fc5b10e7ff8069e1551414"

  strings:
    $s1 = "<Module>{2F03B265-36EC-4B03-917A-18C3F886F2F2}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}