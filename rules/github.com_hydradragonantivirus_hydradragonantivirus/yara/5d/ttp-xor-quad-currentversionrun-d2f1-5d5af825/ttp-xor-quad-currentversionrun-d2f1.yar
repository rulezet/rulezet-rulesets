rule TTP_XOR_QUAD_CurrentVersionRun_d2f1 {
  strings:
    $key_d2f1 = { 81 9e [2] a5 90 [2] 8e bc [2] a0 9e [2] b4 85 [2] bb 9f [2] a5 82 [2] a7 83 [2] bc 85 [2] a0 82 [2] bc ad }

  condition:
    any of them
}