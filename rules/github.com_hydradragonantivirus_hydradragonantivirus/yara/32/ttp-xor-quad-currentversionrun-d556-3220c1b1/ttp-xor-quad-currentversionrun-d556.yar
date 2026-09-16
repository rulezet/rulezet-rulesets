rule TTP_XOR_QUAD_CurrentVersionRun_d556 {
  strings:
    $key_d556 = { 86 39 [2] a2 37 [2] 89 1b [2] a7 39 [2] b3 22 [2] bc 38 [2] a2 25 [2] a0 24 [2] bb 22 [2] a7 25 [2] bb 0a }

  condition:
    any of them
}