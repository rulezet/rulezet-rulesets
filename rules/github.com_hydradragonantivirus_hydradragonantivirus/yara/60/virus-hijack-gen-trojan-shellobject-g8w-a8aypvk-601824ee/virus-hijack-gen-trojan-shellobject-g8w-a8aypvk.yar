rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_a8AyPVk {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@a8AyPVk.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4fb19b782615a70050d9103331c3d05d8898950b8852760ca04a340d7f7de33"

  strings:
    $s1 = " dUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}