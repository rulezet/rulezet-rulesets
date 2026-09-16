rule TTP_XOR_QUAD_CurrentVersionRun_d5fd {
  strings:
    $key_d5fd = { 86 92 [2] a2 9c [2] 89 b0 [2] a7 92 [2] b3 89 [2] bc 93 [2] a2 8e [2] a0 8f [2] bb 89 [2] a7 8e [2] bb a1 }

  condition:
    any of them
}