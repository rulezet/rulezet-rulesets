rule TTP_XOR_QUAD_CurrentVersionRun_2a81 {
  strings:
    $key_2a81 = { 79 ee [2] 5d e0 [2] 76 cc [2] 58 ee [2] 4c f5 [2] 43 ef [2] 5d f2 [2] 5f f3 [2] 44 f5 [2] 58 f2 [2] 44 dd }

  condition:
    any of them
}