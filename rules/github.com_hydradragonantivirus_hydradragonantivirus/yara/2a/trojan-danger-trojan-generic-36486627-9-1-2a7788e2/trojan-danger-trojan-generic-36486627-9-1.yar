rule Trojan_Danger_Trojan_Generic_36486627_9_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.Generic.36486627_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71b28f063a5f7d67aaf3d0afc65e8a992900b9df124a959e457cff1e42e0253c"

  strings:
    $s1 = ".University Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}