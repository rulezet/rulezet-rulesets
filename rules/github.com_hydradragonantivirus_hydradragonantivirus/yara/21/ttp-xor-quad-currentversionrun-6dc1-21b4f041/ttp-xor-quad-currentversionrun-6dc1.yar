rule TTP_XOR_QUAD_CurrentVersionRun_6dc1 {
  strings:
    $key_6dc1 = { 3e ae [2] 1a a0 [2] 31 8c [2] 1f ae [2] 0b b5 [2] 04 af [2] 1a b2 [2] 18 b3 [2] 03 b5 [2] 1f b2 [2] 03 9d }

  condition:
    any of them
}