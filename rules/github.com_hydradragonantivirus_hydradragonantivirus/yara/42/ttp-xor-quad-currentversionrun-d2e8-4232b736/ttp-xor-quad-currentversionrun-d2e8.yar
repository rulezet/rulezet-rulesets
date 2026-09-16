rule TTP_XOR_QUAD_CurrentVersionRun_d2e8 {
  strings:
    $key_d2e8 = { 81 87 [2] a5 89 [2] 8e a5 [2] a0 87 [2] b4 9c [2] bb 86 [2] a5 9b [2] a7 9a [2] bc 9c [2] a0 9b [2] bc b4 }

  condition:
    any of them
}