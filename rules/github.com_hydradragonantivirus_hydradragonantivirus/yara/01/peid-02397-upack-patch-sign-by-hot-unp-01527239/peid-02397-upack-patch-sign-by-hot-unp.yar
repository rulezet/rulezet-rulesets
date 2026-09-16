rule PEiD_02397_Upack_Patch____Sign_by_hot_UNP_ {
  meta:
    description = "[Upack_Patch -> Sign by hot_UNP]"
    ep_only     = "true"

  strings:
    $a = { 81 3A 00 00 00 02 00 00 00 00 }

  condition:
    $a
}