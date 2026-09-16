rule Virus_Hooker_Trojan_GenericKD_48560802_2_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hooker_Trojan.GenericKD.48560802_2_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f546ce9d759fd1262e27860cd6c7970766ba3ef6a143abb4492a9ca81946e344"

  strings:
    $s1 = "[-}4J&GANg" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}