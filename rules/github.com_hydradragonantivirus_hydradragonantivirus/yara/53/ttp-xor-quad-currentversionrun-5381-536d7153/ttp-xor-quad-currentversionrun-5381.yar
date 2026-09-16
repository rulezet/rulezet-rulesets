rule TTP_XOR_QUAD_CurrentVersionRun_5381 {
  strings:
    $key_5381 = { 00 ee [2] 24 e0 [2] 0f cc [2] 21 ee [2] 35 f5 [2] 3a ef [2] 24 f2 [2] 26 f3 [2] 3d f5 [2] 21 f2 [2] 3d dd }

  condition:
    any of them
}