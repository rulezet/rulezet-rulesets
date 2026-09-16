rule PEiD_00475_Ding_Boy_s_PE_lock_v0_07_ {
  meta:
    description = "[Ding Boy's PE-lock v0.07]"
    ep_only     = "true"

  strings:
    $a = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 23 35 40 00 }

  condition:
    $a
}