rule TTP_XOR_QUAD_CurrentVersionRun_09dd {
  strings:
    $key_09dd = { 5a b2 [2] 7e bc [2] 55 90 [2] 7b b2 [2] 6f a9 [2] 60 b3 [2] 7e ae [2] 7c af [2] 67 a9 [2] 7b ae [2] 67 81 }

  condition:
    any of them
}