import "pe"
rule Ding_Boy_s_PE_lock_Phantasm_v1_0___v1_1 {
  strings:
    $a0 = { 55 57 56 52 51 53 66 81 C3 EB 02 EB FC 66 81 C3 EB 02 EB FC }

  condition:
    $a0 at pe.entry_point
}