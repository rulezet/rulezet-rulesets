rule TTP_XOR_QUAD_CurrentVersionRun_4a87 {
  strings:
    $key_4a87 = { 19 e8 [2] 3d e6 [2] 16 ca [2] 38 e8 [2] 2c f3 [2] 23 e9 [2] 3d f4 [2] 3f f5 [2] 24 f3 [2] 38 f4 [2] 24 db }

  condition:
    any of them
}