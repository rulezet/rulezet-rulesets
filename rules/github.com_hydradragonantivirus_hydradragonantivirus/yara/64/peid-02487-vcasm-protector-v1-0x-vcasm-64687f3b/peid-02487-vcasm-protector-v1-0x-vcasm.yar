rule PEiD_02487_VcAsm_Protector_V1_0X____VcAsm_ {
  meta:
    description = "[VcAsm Protector V1.0X -> VcAsm]"
    ep_only     = "true"

  strings:
    $a = { 55 8B EC 6A FF 68 ?? ?? ?? ?? 68 ?? ?? ?? ?? 64 A1 00 00 00 00 50 64 89 25 00 00 00 00 E8 03 00 00 00 }

  condition:
    $a
}