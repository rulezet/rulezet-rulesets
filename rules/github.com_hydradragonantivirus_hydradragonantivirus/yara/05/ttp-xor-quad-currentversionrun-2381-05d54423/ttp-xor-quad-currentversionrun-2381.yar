rule TTP_XOR_QUAD_CurrentVersionRun_2381 {
  strings:
    $key_2381 = { 70 ee [2] 54 e0 [2] 7f cc [2] 51 ee [2] 45 f5 [2] 4a ef [2] 54 f2 [2] 56 f3 [2] 4d f5 [2] 51 f2 [2] 4d dd }

  condition:
    any of them
}