rule TTP_XOR_QUAD_CurrentVersionRun_1281 {
  strings:
    $key_1281 = { 41 ee [2] 65 e0 [2] 4e cc [2] 60 ee [2] 74 f5 [2] 7b ef [2] 65 f2 [2] 67 f3 [2] 7c f5 [2] 60 f2 [2] 7c dd }

  condition:
    any of them
}