rule TTP_XOR_QUAD_CurrentVersionRun_5cc1 {
  strings:
    $key_5cc1 = { 0f ae [2] 2b a0 [2] 00 8c [2] 2e ae [2] 3a b5 [2] 35 af [2] 2b b2 [2] 29 b3 [2] 32 b5 [2] 2e b2 [2] 32 9d }

  condition:
    any of them
}