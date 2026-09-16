rule TTP_XOR_QUAD_CurrentVersionRun_d5e1 {
  strings:
    $key_d5e1 = { 86 8e [2] a2 80 [2] 89 ac [2] a7 8e [2] b3 95 [2] bc 8f [2] a2 92 [2] a0 93 [2] bb 95 [2] a7 92 [2] bb bd }

  condition:
    any of them
}