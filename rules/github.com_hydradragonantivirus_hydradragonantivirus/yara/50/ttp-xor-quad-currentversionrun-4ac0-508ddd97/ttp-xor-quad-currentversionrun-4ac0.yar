rule TTP_XOR_QUAD_CurrentVersionRun_4ac0 {
  strings:
    $key_4ac0 = { 19 af [2] 3d a1 [2] 16 8d [2] 38 af [2] 2c b4 [2] 23 ae [2] 3d b3 [2] 3f b2 [2] 24 b4 [2] 38 b3 [2] 24 9c }

  condition:
    any of them
}