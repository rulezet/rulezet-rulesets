rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aSb8tSc_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aSb8tSc_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cdbe0ed8838b9560315417a0b773b3f1c5d6dce6463c90cd3762158272d43dee"

  strings:
    $s1 = "UH>tweAg" fullword ascii
    $s2 = "BEGO@c" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}