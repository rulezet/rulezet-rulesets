rule Trojan_Danger_Generic_Dacic_1A7FA519_A_003EB174_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Generic.Dacic.1A7FA519.A.003EB174_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ace7eeb1ad769d2b9959ef2c39a4dbfc4caf44ad6c406c2ee9c8175885a30d7"

  strings:
    $s1 = ")tComputer: is defined as the computer on which the programs are installed. A Computer license allows you to use the" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}