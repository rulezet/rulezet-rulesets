rule TTP_XOR_QUAD_CurrentVersionRun_5281 {
  strings:
    $key_5281 = { 01 ee [2] 25 e0 [2] 0e cc [2] 20 ee [2] 34 f5 [2] 3b ef [2] 25 f2 [2] 27 f3 [2] 3c f5 [2] 20 f2 [2] 3c dd }

  condition:
    any of them
}