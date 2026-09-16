rule TTP_XOR_QUAD_CurrentVersionRun_69c1 {
  strings:
    $key_69c1 = { 3a ae [2] 1e a0 [2] 35 8c [2] 1b ae [2] 0f b5 [2] 00 af [2] 1e b2 [2] 1c b3 [2] 07 b5 [2] 1b b2 [2] 07 9d }

  condition:
    any of them
}