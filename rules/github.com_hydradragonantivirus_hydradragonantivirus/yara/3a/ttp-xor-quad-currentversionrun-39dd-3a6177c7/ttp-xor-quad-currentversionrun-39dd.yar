rule TTP_XOR_QUAD_CurrentVersionRun_39dd {
  strings:
    $key_39dd = { 6a b2 [2] 4e bc [2] 65 90 [2] 4b b2 [2] 5f a9 [2] 50 b3 [2] 4e ae [2] 4c af [2] 57 a9 [2] 4b ae [2] 57 81 }

  condition:
    any of them
}