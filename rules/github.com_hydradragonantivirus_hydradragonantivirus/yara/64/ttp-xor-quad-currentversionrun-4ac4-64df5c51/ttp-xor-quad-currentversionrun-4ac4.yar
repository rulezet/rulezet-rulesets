rule TTP_XOR_QUAD_CurrentVersionRun_4ac4 {
  strings:
    $key_4ac4 = { 19 ab [2] 3d a5 [2] 16 89 [2] 38 ab [2] 2c b0 [2] 23 aa [2] 3d b7 [2] 3f b6 [2] 24 b0 [2] 38 b7 [2] 24 98 }

  condition:
    any of them
}