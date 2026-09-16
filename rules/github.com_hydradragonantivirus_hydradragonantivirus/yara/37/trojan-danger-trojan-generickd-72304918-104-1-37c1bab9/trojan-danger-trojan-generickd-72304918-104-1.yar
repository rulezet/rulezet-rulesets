rule Trojan_Danger_Trojan_GenericKD_72304918_104_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72304918_104_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "83dd8c217b34d47a638081aa2fd08b5ceade9cc14d9095f1f238a60646e8f5a6"

  strings:
    $s1 = "hiUniversity Online Library (" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}