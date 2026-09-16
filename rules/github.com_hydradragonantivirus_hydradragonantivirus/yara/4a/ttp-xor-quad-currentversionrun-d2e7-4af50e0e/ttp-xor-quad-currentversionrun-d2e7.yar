rule TTP_XOR_QUAD_CurrentVersionRun_d2e7 {
  strings:
    $key_d2e7 = { 81 88 [2] a5 86 [2] 8e aa [2] a0 88 [2] b4 93 [2] bb 89 [2] a5 94 [2] a7 95 [2] bc 93 [2] a0 94 [2] bc bb }

  condition:
    any of them
}