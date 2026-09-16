rule TTP_XOR_QUAD_CurrentVersionRun_4ac7 {
  strings:
    $key_4ac7 = { 19 a8 [2] 3d a6 [2] 16 8a [2] 38 a8 [2] 2c b3 [2] 23 a9 [2] 3d b4 [2] 3f b5 [2] 24 b3 [2] 38 b4 [2] 24 9b }

  condition:
    any of them
}