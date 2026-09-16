rule TTP_XOR_QUAD_CurrentVersionRun_4ac3 {
  strings:
    $key_4ac3 = { 19 ac [2] 3d a2 [2] 16 8e [2] 38 ac [2] 2c b7 [2] 23 ad [2] 3d b0 [2] 3f b1 [2] 24 b7 [2] 38 b0 [2] 24 9f }

  condition:
    any of them
}