rule TTP_XOR_QUAD_CurrentVersionRun_79dd {
  strings:
    $key_79dd = { 2a b2 [2] 0e bc [2] 25 90 [2] 0b b2 [2] 1f a9 [2] 10 b3 [2] 0e ae [2] 0c af [2] 17 a9 [2] 0b ae [2] 17 81 }

  condition:
    any of them
}