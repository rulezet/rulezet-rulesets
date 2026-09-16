rule Virus_Hijack_Gen_Trojan_ShellObject_IyZ_aCEmdoo_10_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.IyZ@aCEmdoo_10_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7c0e2e8596cbbb5d5b93690ee0a20e8e2f3d89398eed6bcfd54507327bd58b8"

  strings:
    $s1 = "COMPUTER BILD Digital GmbH1" fullword ascii
    $s2 = "COMPUTER BILD Digital GmbH0" fullword ascii
    $s3 = "@Floating point (%%e, %%f, %%g, and %%G) is not supported by the WTL::CString class." fullword wide
    $s4 = "voAR$8P*" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}