rule Virus_Hijack_Trojan_GenericKDZ_103285_147 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.103285_147.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ec1988691758f7642a2a0b74f54bf781a484c5c5eaa2a5bb4a92e10ad475063e"

  strings:
    $s1 = "DQWhat if Microsoft breaches its warranty? If Microsoft breaches its limited warranty, your only" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}