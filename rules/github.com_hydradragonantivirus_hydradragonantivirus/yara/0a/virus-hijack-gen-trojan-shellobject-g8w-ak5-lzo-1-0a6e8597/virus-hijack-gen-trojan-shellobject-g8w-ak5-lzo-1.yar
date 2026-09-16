rule Virus_Hijack_Gen_Trojan_ShellObject_g8W_aK5_lZo_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.g8W@aK5!lZo_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fb6ff5a61223981f53d01c9a875052aacf33bb36e6c1006536ea272f6d7f2c4f"

  strings:
    $s1 = "_University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}