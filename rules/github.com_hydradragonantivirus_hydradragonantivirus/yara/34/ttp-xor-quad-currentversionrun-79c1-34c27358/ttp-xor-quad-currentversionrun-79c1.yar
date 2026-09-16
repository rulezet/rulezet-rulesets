rule TTP_XOR_QUAD_CurrentVersionRun_79c1 {
  strings:
    $key_79c1 = { 2a ae [2] 0e a0 [2] 25 8c [2] 0b ae [2] 1f b5 [2] 10 af [2] 0e b2 [2] 0c b3 [2] 17 b5 [2] 0b b2 [2] 17 9d }

  condition:
    any of them
}