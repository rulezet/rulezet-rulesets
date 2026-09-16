rule TTP_XOR_QUAD_CurrentVersionRun_d55a {
  strings:
    $key_d55a = { 86 35 [2] a2 3b [2] 89 17 [2] a7 35 [2] b3 2e [2] bc 34 [2] a2 29 [2] a0 28 [2] bb 2e [2] a7 29 [2] bb 06 }

  condition:
    any of them
}