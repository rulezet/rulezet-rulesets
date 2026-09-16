rule PEiD_02491_Vcasm_Protector_1_0a___1_0d____vcasm_ {
  meta:
    description = "[Vcasm-Protector 1.0a - 1.0d -> vcasm]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 ?? ?? ?? 00 68 ?? ?? ?? 00 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 }

  condition:
    $a
}