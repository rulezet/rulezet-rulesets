rule Virus_Hijack_Gen_Trojan_ShellObject_k4Z_a8_cJFh_5 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.k4Z@a8!cJFh_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e17cc9a9a77bfdf3b3aab4ce0316261640a1d92ad46c4b272621e15d74ecc6d3"

  strings:
    $s1 = "~}Oracle University Online Service: the Oracle University Online Service is a web based learning environment comprised of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}