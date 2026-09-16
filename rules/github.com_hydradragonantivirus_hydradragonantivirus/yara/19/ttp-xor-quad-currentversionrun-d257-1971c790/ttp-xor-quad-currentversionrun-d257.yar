rule TTP_XOR_QUAD_CurrentVersionRun_d257 {
  strings:
    $key_d257 = { 81 38 [2] a5 36 [2] 8e 1a [2] a0 38 [2] b4 23 [2] bb 39 [2] a5 24 [2] a7 25 [2] bc 23 [2] a0 24 [2] bc 0b }

  condition:
    any of them
}