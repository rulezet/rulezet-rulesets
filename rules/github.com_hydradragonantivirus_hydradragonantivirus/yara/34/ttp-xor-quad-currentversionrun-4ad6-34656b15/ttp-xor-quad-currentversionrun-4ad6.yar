rule TTP_XOR_QUAD_CurrentVersionRun_4ad6 {
  strings:
    $key_4ad6 = { 19 b9 [2] 3d b7 [2] 16 9b [2] 38 b9 [2] 2c a2 [2] 23 b8 [2] 3d a5 [2] 3f a4 [2] 24 a2 [2] 38 a5 [2] 24 8a }

  condition:
    any of them
}