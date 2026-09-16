rule Virus_Hijack_Gen_Trojan_ShellObject_f8W_ayWIjmh_3 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.f8W@ayWIjmh_3.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fd402ab59258502e0a4b958cb3e7b13bf608ec9b23c4aeed64b205383952f0ff"

  strings:
    $s1 = "TO RESOLVE A DISPUTE WITH THE MA NUFA CTURER OR INSTALLER, OR`" fullword ascii
    $s2 = "Tyour order when licensing these applications.)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}