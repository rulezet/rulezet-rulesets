rule Trojan_Danger_Trojan_GenericKD_72677122_227_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_227_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "330c12e6b83dc95b2bc00c961082db6b94b072f397e5a8c465c67d30f542a1a0"

  strings:
    $s1 = "HKCU\\Software\\Microsoft\\Internet Explorer\\Main\\Start Page" fullword wide
    $s2 = "echo Y| cacls " fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}