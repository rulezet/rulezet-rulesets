rule TTP_XOR_QUAD_CurrentVersionRun_d237 {
  strings:
    $key_d237 = { 81 58 [2] a5 56 [2] 8e 7a [2] a0 58 [2] b4 43 [2] bb 59 [2] a5 44 [2] a7 45 [2] bc 43 [2] a0 44 [2] bc 6b }

  condition:
    any of them
}