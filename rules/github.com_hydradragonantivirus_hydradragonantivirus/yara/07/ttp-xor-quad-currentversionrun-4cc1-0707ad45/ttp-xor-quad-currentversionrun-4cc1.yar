rule TTP_XOR_QUAD_CurrentVersionRun_4cc1 {
  strings:
    $key_4cc1 = { 1f ae [2] 3b a0 [2] 10 8c [2] 3e ae [2] 2a b5 [2] 25 af [2] 3b b2 [2] 39 b3 [2] 22 b5 [2] 3e b2 [2] 22 9d }

  condition:
    any of them
}