rule TTP_XOR_QUAD_CurrentVersionRun_1dc1 {
  strings:
    $key_1dc1 = { 4e ae [2] 6a a0 [2] 41 8c [2] 6f ae [2] 7b b5 [2] 74 af [2] 6a b2 [2] 68 b3 [2] 73 b5 [2] 6f b2 [2] 73 9d }

  condition:
    any of them
}