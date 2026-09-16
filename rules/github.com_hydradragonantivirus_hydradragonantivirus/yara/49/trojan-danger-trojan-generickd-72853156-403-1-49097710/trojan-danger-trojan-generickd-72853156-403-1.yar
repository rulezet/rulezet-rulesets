rule Trojan_Danger_Trojan_GenericKD_72853156_403_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_403_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e19cdd67b2b4eea386c39d4696b224baf11eaf19ae1fc4837669f8e866db0b24"

  strings:
    $s1 = "E%d is an invalid PageIndex value.  PageIndex must be between 0 and %d" fullword wide
    $s2 = "Cannot assign a %s to a %s List capacity out of bounds (%d)" fullword wide
    $s3 = "List index out of bounds (%d)#''%s'' is not a valid integer value&Cannot change the size of a JPEG image" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}