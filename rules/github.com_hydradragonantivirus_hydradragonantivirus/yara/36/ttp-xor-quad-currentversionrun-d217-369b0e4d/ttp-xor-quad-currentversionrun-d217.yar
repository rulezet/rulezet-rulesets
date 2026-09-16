rule TTP_XOR_QUAD_CurrentVersionRun_d217 {
  strings:
    $key_d217 = { 81 78 [2] a5 76 [2] 8e 5a [2] a0 78 [2] b4 63 [2] bb 79 [2] a5 64 [2] a7 65 [2] bc 63 [2] a0 64 [2] bc 4b }

  condition:
    any of them
}