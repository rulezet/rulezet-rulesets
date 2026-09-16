rule TTP_XOR_QUAD_CurrentVersionRun_7cc1 {
  strings:
    $key_7cc1 = { 2f ae [2] 0b a0 [2] 20 8c [2] 0e ae [2] 1a b5 [2] 15 af [2] 0b b2 [2] 09 b3 [2] 12 b5 [2] 0e b2 [2] 12 9d }

  condition:
    any of them
}