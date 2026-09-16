rule Virus_Hijack_Gen_Trojan_ShellObject_v8Z_au0WBJh_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.v8Z@au0WBJh_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30124daac25023552f5d270df5ffaa91f652acf4a9e95be72314170dbb658958"

  strings:
    $s1 = "Forders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}