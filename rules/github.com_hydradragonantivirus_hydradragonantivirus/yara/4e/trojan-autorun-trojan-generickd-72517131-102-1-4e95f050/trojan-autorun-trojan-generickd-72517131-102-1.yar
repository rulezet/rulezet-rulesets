rule Trojan_Autorun_Trojan_GenericKD_72517131_102_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.72517131_102_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b75378cda31a11106cfe9136cb5b58f3c1abdad4b7a11bc22f67c8e74c7b795f"

  strings:
    $s1 = "required and all actual users must be license" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}