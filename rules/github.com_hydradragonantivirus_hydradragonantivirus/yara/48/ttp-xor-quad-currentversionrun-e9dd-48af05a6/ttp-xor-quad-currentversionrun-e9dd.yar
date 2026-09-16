rule TTP_XOR_QUAD_CurrentVersionRun_e9dd {
  strings:
    $key_e9dd = { ba b2 [2] 9e bc [2] b5 90 [2] 9b b2 [2] 8f a9 [2] 80 b3 [2] 9e ae [2] 9c af [2] 87 a9 [2] 9b ae [2] 87 81 }

  condition:
    any of them
}