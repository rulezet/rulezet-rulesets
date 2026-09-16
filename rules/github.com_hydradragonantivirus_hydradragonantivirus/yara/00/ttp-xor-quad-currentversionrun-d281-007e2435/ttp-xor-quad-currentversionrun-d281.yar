rule TTP_XOR_QUAD_CurrentVersionRun_d281 {
  strings:
    $key_d281 = { 81 ee [2] a5 e0 [2] 8e cc [2] a0 ee [2] b4 f5 [2] bb ef [2] a5 f2 [2] a7 f3 [2] bc f5 [2] a0 f2 [2] bc dd }

  condition:
    any of them
}