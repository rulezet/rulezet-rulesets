rule TTP_XOR_QUAD_CurrentVersionRun_4ad5 {
  strings:
    $key_4ad5 = { 19 ba [2] 3d b4 [2] 16 98 [2] 38 ba [2] 2c a1 [2] 23 bb [2] 3d a6 [2] 3f a7 [2] 24 a1 [2] 38 a6 [2] 24 89 }

  condition:
    any of them
}