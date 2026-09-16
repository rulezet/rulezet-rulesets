rule Virus_Hijack_Trojan_GenericKDZ_103285_745 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_745.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ddc8121232a69453e77cc0804ae2acc8b502c67c8c19a60b91afaf8e6e6c4c20"

  strings:
    $s1 = "Lpolicy, which might require you to return the software with the entire computer on which the software is" fullword ascii
    $s2 = "If you have a dispute with Oracle or if you wish to provide a notice under the `" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}