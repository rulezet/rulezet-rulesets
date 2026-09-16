rule Trojan_Danger_Trojan_GenericKD_67166905_219_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.67166905_219_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4849dd8914c869542e8367336dd95b33780b3f60923fa27ee0da526c79bc09c4"

  strings:
    $s1 = "Ppurposes of counting the number of processors which require licensing, a multicore chip with \"n\" processor cores shall be" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}