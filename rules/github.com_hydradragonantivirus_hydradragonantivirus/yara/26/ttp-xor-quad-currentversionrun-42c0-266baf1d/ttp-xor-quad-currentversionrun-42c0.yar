rule TTP_XOR_QUAD_CurrentVersionRun_42c0 {
  strings:
    $key_42c0 = { 11 af [2] 35 a1 [2] 1e 8d [2] 30 af [2] 24 b4 [2] 2b ae [2] 35 b3 [2] 37 b2 [2] 2c b4 [2] 30 b3 [2] 2c 9c }

  condition:
    any of them
}