rule PEiD_00473_Ding_Boy_s_PE_lock_Phantasm_v1_0___v1_1_ {
  meta:
    description = "[Ding Boy's PE-lock Phantasm v1.0 / v1.1]"
    ep_only     = "true"

  strings:
    $a = { 55 57 56 52 51 53 66 81 C3 EB 02 EB FC 66 81 C3 EB 02 EB FC }

  condition:
    $a
}