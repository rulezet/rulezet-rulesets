rule TTP_XOR_QUAD_CurrentVersionRun_d523 {
  strings:
    $key_d523 = { 86 4c [2] a2 42 [2] 89 6e [2] a7 4c [2] b3 57 [2] bc 4d [2] a2 50 [2] a0 51 [2] bb 57 [2] a7 50 [2] bb 7f }

  condition:
    any of them
}