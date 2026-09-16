rule Virus_Hijack_Gen_Trojan_ShellObject_fWW_ayzr0Ib_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.fWW@ayzr0Ib_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99e893c38a453688ac82683233a1ec7dbe7b53b64c34e159959d19739c277057"

  strings:
    $s1 = "spurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}