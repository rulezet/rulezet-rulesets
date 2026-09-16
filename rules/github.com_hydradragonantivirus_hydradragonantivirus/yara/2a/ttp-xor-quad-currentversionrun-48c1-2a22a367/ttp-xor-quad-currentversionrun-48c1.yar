rule TTP_XOR_QUAD_CurrentVersionRun_48c1 {
  strings:
    $key_48c1 = { 1b ae [2] 3f a0 [2] 14 8c [2] 3a ae [2] 2e b5 [2] 21 af [2] 3f b2 [2] 3d b3 [2] 26 b5 [2] 3a b2 [2] 26 9d }

  condition:
    any of them
}