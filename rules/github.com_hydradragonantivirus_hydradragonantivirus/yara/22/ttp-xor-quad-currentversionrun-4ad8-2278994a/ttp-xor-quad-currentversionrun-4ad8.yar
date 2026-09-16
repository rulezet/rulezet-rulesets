rule TTP_XOR_QUAD_CurrentVersionRun_4ad8 {
  strings:
    $key_4ad8 = { 19 b7 [2] 3d b9 [2] 16 95 [2] 38 b7 [2] 2c ac [2] 23 b6 [2] 3d ab [2] 3f aa [2] 24 ac [2] 38 ab [2] 24 84 }

  condition:
    any of them
}