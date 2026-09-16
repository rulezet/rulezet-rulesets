rule TTP_XOR_QUAD_CurrentVersionRun_4ac2 {
  strings:
    $key_4ac2 = { 19 ad [2] 3d a3 [2] 16 8f [2] 38 ad [2] 2c b6 [2] 23 ac [2] 3d b1 [2] 3f b0 [2] 24 b6 [2] 38 b1 [2] 24 9e }

  condition:
    any of them
}