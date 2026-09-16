rule TTP_XOR_QUAD_CurrentVersionRun_3dc1 {
  strings:
    $key_3dc1 = { 6e ae [2] 4a a0 [2] 61 8c [2] 4f ae [2] 5b b5 [2] 54 af [2] 4a b2 [2] 48 b3 [2] 53 b5 [2] 4f b2 [2] 53 9d }

  condition:
    any of them
}