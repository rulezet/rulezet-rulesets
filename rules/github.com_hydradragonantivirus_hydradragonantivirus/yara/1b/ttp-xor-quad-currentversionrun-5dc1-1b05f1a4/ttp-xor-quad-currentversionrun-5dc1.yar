rule TTP_XOR_QUAD_CurrentVersionRun_5dc1 {
  strings:
    $key_5dc1 = { 0e ae [2] 2a a0 [2] 01 8c [2] 2f ae [2] 3b b5 [2] 34 af [2] 2a b2 [2] 28 b3 [2] 33 b5 [2] 2f b2 [2] 33 9d }

  condition:
    any of them
}