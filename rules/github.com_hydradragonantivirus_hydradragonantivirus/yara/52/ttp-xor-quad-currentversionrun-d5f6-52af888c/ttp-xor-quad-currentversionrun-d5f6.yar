rule TTP_XOR_QUAD_CurrentVersionRun_d5f6 {
  strings:
    $key_d5f6 = { 86 99 [2] a2 97 [2] 89 bb [2] a7 99 [2] b3 82 [2] bc 98 [2] a2 85 [2] a0 84 [2] bb 82 [2] a7 85 [2] bb aa }

  condition:
    any of them
}