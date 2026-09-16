rule TTP_XOR_QUAD_CurrentVersionRun_58c1 {
  strings:
    $key_58c1 = { 0b ae [2] 2f a0 [2] 04 8c [2] 2a ae [2] 3e b5 [2] 31 af [2] 2f b2 [2] 2d b3 [2] 36 b5 [2] 2a b2 [2] 36 9d }

  condition:
    any of them
}