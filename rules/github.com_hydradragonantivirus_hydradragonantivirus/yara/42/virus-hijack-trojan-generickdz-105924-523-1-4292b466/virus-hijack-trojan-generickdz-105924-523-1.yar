rule Virus_Hijack_Trojan_GenericKDZ_105924_523_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.105924_523_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d146ebc138e224681a92069b7304b057ccc3c4fd5ee823011f7851bbd8f3c8b7"

  strings:
    $s1 = "cRoss*" fullword ascii
    $s2 = "}`fIKE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}