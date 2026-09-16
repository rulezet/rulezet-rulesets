rule TTP_XOR_QUAD_CurrentVersionRun_78c1 {
  strings:
    $key_78c1 = { 2b ae [2] 0f a0 [2] 24 8c [2] 0a ae [2] 1e b5 [2] 11 af [2] 0f b2 [2] 0d b3 [2] 16 b5 [2] 0a b2 [2] 16 9d }

  condition:
    any of them
}