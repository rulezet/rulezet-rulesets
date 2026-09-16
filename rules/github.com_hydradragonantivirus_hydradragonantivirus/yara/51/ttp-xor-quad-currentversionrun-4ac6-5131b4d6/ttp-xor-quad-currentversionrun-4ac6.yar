rule TTP_XOR_QUAD_CurrentVersionRun_4ac6 {
  strings:
    $key_4ac6 = { 19 a9 [2] 3d a7 [2] 16 8b [2] 38 a9 [2] 2c b2 [2] 23 a8 [2] 3d b5 [2] 3f b4 [2] 24 b2 [2] 38 b5 [2] 24 9a }

  condition:
    any of them
}