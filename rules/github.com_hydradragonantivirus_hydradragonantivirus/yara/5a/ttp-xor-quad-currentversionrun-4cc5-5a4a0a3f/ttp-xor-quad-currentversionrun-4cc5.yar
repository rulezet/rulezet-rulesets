rule TTP_XOR_QUAD_CurrentVersionRun_4cc5 {
  strings:
    $key_4cc5 = { 1f aa [2] 3b a4 [2] 10 88 [2] 3e aa [2] 2a b1 [2] 25 ab [2] 3b b6 [2] 39 b7 [2] 22 b1 [2] 3e b6 [2] 22 99 }

  condition:
    any of them
}