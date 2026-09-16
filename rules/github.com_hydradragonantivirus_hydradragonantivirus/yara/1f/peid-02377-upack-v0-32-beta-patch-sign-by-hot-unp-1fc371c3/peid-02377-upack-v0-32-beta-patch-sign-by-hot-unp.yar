rule PEiD_02377_Upack_v0_32_Beta__Patch_____Sign_by_hot_UNP_ {
  meta:
    description = "[Upack v0.32 Beta (Patch) -> Sign by hot_UNP]"
    ep_only     = "false"

  strings:
    $a = { BE 88 01 ?? ?? AD 50 ?? AD 91 F3 A5 }

  condition:
    $a
}