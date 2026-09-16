rule TTP_XOR_QUAD_CurrentVersionRun_d501 {
  strings:
    $key_d501 = { 86 6e [2] a2 60 [2] 89 4c [2] a7 6e [2] b3 75 [2] bc 6f [2] a2 72 [2] a0 73 [2] bb 75 [2] a7 72 [2] bb 5d }

  condition:
    any of them
}