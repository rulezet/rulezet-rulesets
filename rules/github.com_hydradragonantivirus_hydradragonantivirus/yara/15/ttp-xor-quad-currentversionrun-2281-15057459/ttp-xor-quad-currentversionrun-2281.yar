rule TTP_XOR_QUAD_CurrentVersionRun_2281 {
  strings:
    $key_2281 = { 71 ee [2] 55 e0 [2] 7e cc [2] 50 ee [2] 44 f5 [2] 4b ef [2] 55 f2 [2] 57 f3 [2] 4c f5 [2] 50 f2 [2] 4c dd }

  condition:
    any of them
}