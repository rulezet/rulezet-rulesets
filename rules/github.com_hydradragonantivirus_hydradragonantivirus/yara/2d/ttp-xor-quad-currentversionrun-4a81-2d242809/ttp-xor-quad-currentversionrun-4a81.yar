rule TTP_XOR_QUAD_CurrentVersionRun_4a81 {
  strings:
    $key_4a81 = { 19 ee [2] 3d e0 [2] 16 cc [2] 38 ee [2] 2c f5 [2] 23 ef [2] 3d f2 [2] 3f f3 [2] 24 f5 [2] 38 f2 [2] 24 dd }

  condition:
    any of them
}