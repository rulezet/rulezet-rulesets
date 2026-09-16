rule TTP_XOR_QUAD_CurrentVersionRun_d215 {
  strings:
    $key_d215 = { 81 7a [2] a5 74 [2] 8e 58 [2] a0 7a [2] b4 61 [2] bb 7b [2] a5 66 [2] a7 67 [2] bc 61 [2] a0 66 [2] bc 49 }

  condition:
    any of them
}