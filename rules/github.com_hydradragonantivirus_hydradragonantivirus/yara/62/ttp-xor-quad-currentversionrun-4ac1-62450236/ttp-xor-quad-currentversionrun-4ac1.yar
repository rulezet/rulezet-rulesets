rule TTP_XOR_QUAD_CurrentVersionRun_4ac1 {
  strings:
    $key_4ac1 = { 19 ae [2] 3d a0 [2] 16 8c [2] 38 ae [2] 2c b5 [2] 23 af [2] 3d b2 [2] 3f b3 [2] 24 b5 [2] 38 b2 [2] 24 9d }

  condition:
    any of them
}