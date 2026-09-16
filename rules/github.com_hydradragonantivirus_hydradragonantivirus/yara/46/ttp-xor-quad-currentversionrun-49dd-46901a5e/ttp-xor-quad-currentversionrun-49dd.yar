rule TTP_XOR_QUAD_CurrentVersionRun_49dd {
  strings:
    $key_49dd = { 1a b2 [2] 3e bc [2] 15 90 [2] 3b b2 [2] 2f a9 [2] 20 b3 [2] 3e ae [2] 3c af [2] 27 a9 [2] 3b ae [2] 27 81 }

  condition:
    any of them
}