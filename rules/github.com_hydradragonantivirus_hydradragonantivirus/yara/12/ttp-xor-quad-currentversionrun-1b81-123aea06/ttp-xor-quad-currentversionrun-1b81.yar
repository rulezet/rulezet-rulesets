rule TTP_XOR_QUAD_CurrentVersionRun_1b81 {
  strings:
    $key_1b81 = { 48 ee [2] 6c e0 [2] 47 cc [2] 69 ee [2] 7d f5 [2] 72 ef [2] 6c f2 [2] 6e f3 [2] 75 f5 [2] 69 f2 [2] 75 dd }

  condition:
    any of them
}