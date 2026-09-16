rule TTP_XOR_QUAD_CurrentVersionRun_59c1 {
  strings:
    $key_59c1 = { 0a ae [2] 2e a0 [2] 05 8c [2] 2b ae [2] 3f b5 [2] 30 af [2] 2e b2 [2] 2c b3 [2] 37 b5 [2] 2b b2 [2] 37 9d }

  condition:
    any of them
}