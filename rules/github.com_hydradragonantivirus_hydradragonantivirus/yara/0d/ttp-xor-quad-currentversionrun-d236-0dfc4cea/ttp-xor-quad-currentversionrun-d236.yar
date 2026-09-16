rule TTP_XOR_QUAD_CurrentVersionRun_d236 {
  strings:
    $key_d236 = { 81 59 [2] a5 57 [2] 8e 7b [2] a0 59 [2] b4 42 [2] bb 58 [2] a5 45 [2] a7 44 [2] bc 42 [2] a0 45 [2] bc 6a }

  condition:
    any of them
}