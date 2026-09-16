rule TTP_XOR_QUAD_CurrentVersionRun_5a81 {
  strings:
    $key_5a81 = { 09 ee [2] 2d e0 [2] 06 cc [2] 28 ee [2] 3c f5 [2] 33 ef [2] 2d f2 [2] 2f f3 [2] 34 f5 [2] 28 f2 [2] 34 dd }

  condition:
    any of them
}