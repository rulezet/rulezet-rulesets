rule TTP_XOR_QUAD_CurrentVersionRun_d5f3 {
  strings:
    $key_d5f3 = { 86 9c [2] a2 92 [2] 89 be [2] a7 9c [2] b3 87 [2] bc 9d [2] a2 80 [2] a0 81 [2] bb 87 [2] a7 80 [2] bb af }

  condition:
    any of them
}