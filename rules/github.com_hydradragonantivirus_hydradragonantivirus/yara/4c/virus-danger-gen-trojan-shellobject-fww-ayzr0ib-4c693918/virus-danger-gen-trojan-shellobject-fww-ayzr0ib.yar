rule Virus_Danger_Gen_Trojan_ShellObject_fWW_ayzr0Ib {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.fWW@ayzr0Ib.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f82126eab864e657b9f1ae44590154eb281bc7b3b25ea8810c73d894ef5ac456"

  strings:
    $s1 = "/purposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}