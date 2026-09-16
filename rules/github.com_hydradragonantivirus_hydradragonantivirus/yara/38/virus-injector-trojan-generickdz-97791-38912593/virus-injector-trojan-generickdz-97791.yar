rule Virus_Injector_Trojan_GenericKDZ_97791 {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Trojan.GenericKDZ.97791.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e4d138005748d27af01010b4e83b75f2c2bcb5a7e7d89c2debfcb77681c6ccec"

  strings:
    $s1 = "VJava(TM) SE Runtime Environment 6 Update 3" fullword wide
    $s2 = "Java(TM) Platform SE 6 U30" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}