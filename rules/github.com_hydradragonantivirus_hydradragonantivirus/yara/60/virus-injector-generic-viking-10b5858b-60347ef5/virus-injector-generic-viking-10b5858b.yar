rule Virus_Injector_Generic_Viking_10B5858B {
  meta:
    description = "datamaliciousorder - file Virus.Injector_Generic.Viking.10B5858B.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dce88aad8945e932e2b8d2cb1e96e4c7cb99c6b8a5ee42d96e6742463640c681"

  strings:
    $s1 = "Executing INF-File: %ws (Section: %ws) ..." fullword wide
    $s2 = "aLky;," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}