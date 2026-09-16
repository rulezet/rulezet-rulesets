rule TTP_XOR_QUAD_CurrentVersionRun_dad1 {
  strings:
    $key_dad1 = { 89 be [2] ad b0 [2] 86 9c [2] a8 be [2] bc a5 [2] b3 bf [2] ad a2 [2] af a3 [2] b4 a5 [2] a8 a2 [2] b4 8d }

  condition:
    any of them
}