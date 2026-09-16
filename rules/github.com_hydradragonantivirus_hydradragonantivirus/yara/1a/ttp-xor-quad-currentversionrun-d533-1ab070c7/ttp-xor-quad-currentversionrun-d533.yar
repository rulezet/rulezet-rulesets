rule TTP_XOR_QUAD_CurrentVersionRun_d533 {
  strings:
    $key_d533 = { 86 5c [2] a2 52 [2] 89 7e [2] a7 5c [2] b3 47 [2] bc 5d [2] a2 40 [2] a0 41 [2] bb 47 [2] a7 40 [2] bb 6f }

  condition:
    any of them
}