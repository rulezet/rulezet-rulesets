rule TTP_XOR_QUAD_CurrentVersionRun_08c1 {
  strings:
    $key_08c1 = { 5b ae [2] 7f a0 [2] 54 8c [2] 7a ae [2] 6e b5 [2] 61 af [2] 7f b2 [2] 7d b3 [2] 66 b5 [2] 7a b2 [2] 66 9d }

  condition:
    any of them
}