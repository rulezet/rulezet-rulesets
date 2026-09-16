rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_amCvSwc {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@amCvSwc.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58796f50cce2a9e609ddfc73462b1f87402694acea56cee985f48216ecca3e99"

  strings:
    $s1 = "<University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}