rule TTP_XOR_QUAD_CurrentVersionRun_1ac0 {
  strings:
    $key_1ac0 = { 49 af [2] 6d a1 [2] 46 8d [2] 68 af [2] 7c b4 [2] 73 ae [2] 6d b3 [2] 6f b2 [2] 74 b4 [2] 68 b3 [2] 74 9c }

  condition:
    any of them
}