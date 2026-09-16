rule TTP_XOR_QUAD_CurrentVersionRun_d24b {
  strings:
    $key_d24b = { 81 24 [2] a5 2a [2] 8e 06 [2] a0 24 [2] b4 3f [2] bb 25 [2] a5 38 [2] a7 39 [2] bc 3f [2] a0 38 [2] bc 17 }

  condition:
    any of them
}