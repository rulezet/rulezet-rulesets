rule PEiD_00472_Ding_Boy_s_PE_lock_Phantasm_v0_8_ {
  meta:
    description = "[Ding Boy's PE-lock Phantasm v0.8]"
    ep_only     = "true"

  strings:
    $a = { 55 57 56 52 51 53 E8 00 00 00 00 5D 8B D5 81 ED 0D 39 40 00 }

  condition:
    $a
}