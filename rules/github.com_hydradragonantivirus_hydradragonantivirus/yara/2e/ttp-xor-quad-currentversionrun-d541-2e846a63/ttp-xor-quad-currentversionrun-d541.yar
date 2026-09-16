rule TTP_XOR_QUAD_CurrentVersionRun_d541 {
  strings:
    $key_d541 = { 86 2e [2] a2 20 [2] 89 0c [2] a7 2e [2] b3 35 [2] bc 2f [2] a2 32 [2] a0 33 [2] bb 35 [2] a7 32 [2] bb 1d }

  condition:
    any of them
}