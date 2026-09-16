rule TTP_XOR_QUAD_CurrentVersionRun_d503 {
  strings:
    $key_d503 = { 86 6c [2] a2 62 [2] 89 4e [2] a7 6c [2] b3 77 [2] bc 6d [2] a2 70 [2] a0 71 [2] bb 77 [2] a7 70 [2] bb 5f }

  condition:
    any of them
}