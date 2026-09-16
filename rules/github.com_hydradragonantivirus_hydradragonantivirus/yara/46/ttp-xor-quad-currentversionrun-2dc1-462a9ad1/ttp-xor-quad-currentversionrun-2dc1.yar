rule TTP_XOR_QUAD_CurrentVersionRun_2dc1 {
  strings:
    $key_2dc1 = { 7e ae [2] 5a a0 [2] 71 8c [2] 5f ae [2] 4b b5 [2] 44 af [2] 5a b2 [2] 58 b3 [2] 43 b5 [2] 5f b2 [2] 43 9d }

  condition:
    any of them
}