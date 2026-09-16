rule TTP_XOR_QUAD_CurrentVersionRun_0b81 {
  strings:
    $key_0b81 = { 58 ee [2] 7c e0 [2] 57 cc [2] 79 ee [2] 6d f5 [2] 62 ef [2] 7c f2 [2] 7e f3 [2] 65 f5 [2] 79 f2 [2] 65 dd }

  condition:
    any of them
}