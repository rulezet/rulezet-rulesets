rule TTP_XOR_QUAD_CurrentVersionRun_4ad7 {
  strings:
    $key_4ad7 = { 19 b8 [2] 3d b6 [2] 16 9a [2] 38 b8 [2] 2c a3 [2] 23 b9 [2] 3d a4 [2] 3f a5 [2] 24 a3 [2] 38 a4 [2] 24 8b }

  condition:
    any of them
}