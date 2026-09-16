rule Virus_Hijack_Trojan_GenericKDZ_103285_53 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_53.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dfc0c770e3ab0cc222ca361984a55dc5743efcd60b30d7b9b456d400ba89216c"

  strings:
    $s1 = "Qmust be a Qualified Educational User to use software marked as " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}