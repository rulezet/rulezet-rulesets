rule Trojan_Danger_Trojan_GenericKD_72853156_399_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_399_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aa97d7e724a4fb32e3efd369c79013f32f574661d6f4ecaf6c7561c1bb3f362e"

  strings:
    $s1 = "REFUSE" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}