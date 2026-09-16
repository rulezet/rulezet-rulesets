rule Virus_Hijack_Trojan_GenericKDZ_98388_126_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98388_126_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "349359bc305edee0c2520142984185f6531ca21aa106f1d0ccd8bd14b78d73fb"

  strings:
    $s1 = "aKin`05" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}