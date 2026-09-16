rule TTP_XOR_QUAD_CurrentVersionRun_4ac5 {
  strings:
    $key_4ac5 = { 19 aa [2] 3d a4 [2] 16 88 [2] 38 aa [2] 2c b1 [2] 23 ab [2] 3d b6 [2] 3f b7 [2] 24 b1 [2] 38 b6 [2] 24 99 }

  condition:
    any of them
}