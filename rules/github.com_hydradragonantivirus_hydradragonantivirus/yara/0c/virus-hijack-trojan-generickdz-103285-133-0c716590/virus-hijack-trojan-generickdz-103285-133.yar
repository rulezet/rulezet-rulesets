rule Virus_Hijack_Trojan_GenericKDZ_103285_133 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_133.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f66d0b627b9f3b0e270ba1b8d28972ea5933dd2e72775ccef9ea9d4b1ea027ee"

  strings:
    $s1 = "YNUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}