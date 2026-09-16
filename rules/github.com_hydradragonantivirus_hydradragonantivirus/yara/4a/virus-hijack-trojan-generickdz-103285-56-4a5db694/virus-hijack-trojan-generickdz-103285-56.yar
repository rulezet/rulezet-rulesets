rule Virus_Hijack_Trojan_GenericKDZ_103285_56 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_56.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b81219714992015b4ff3bc2f34bcc870e6177c4bc1893cada5c044a5d320581b"

  strings:
    $s1 = "Seck@i" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}