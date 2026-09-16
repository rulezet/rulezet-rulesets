rule PEiD_02385_Upack_v0_36_alpha____Sign_by_hot_UNP_ {
  meta:
    description = "[Upack v0.36 alpha -> Sign by hot_UNP]"
    ep_only     = "false"

  strings:
    $a = { AB E2 E5 5D 59 8B 76 68 51 59 46 AD 85 C0 }

  condition:
    $a
}