rule TTP_XOR_QUAD_CurrentVersionRun_4a80 {
  strings:
    $key_4a80 = { 19 ef [2] 3d e1 [2] 16 cd [2] 38 ef [2] 2c f4 [2] 23 ee [2] 3d f3 [2] 3f f2 [2] 24 f4 [2] 38 f3 [2] 24 dc }

  condition:
    any of them
}