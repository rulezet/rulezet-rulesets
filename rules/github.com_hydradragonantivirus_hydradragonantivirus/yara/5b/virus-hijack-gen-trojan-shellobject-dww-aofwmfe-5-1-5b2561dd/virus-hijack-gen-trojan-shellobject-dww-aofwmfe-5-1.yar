rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c94132d698e70e168719e26b616754e8fe5629f9f2d581ac3c531707087554d9"

  strings:
    $s1 = "<embed autoplay=\"true\" src=\"sound.mp3\"  width=\"1\" height=\"1\" />" fullword ascii
    $s2 = "function time(){return Math.random()}" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}