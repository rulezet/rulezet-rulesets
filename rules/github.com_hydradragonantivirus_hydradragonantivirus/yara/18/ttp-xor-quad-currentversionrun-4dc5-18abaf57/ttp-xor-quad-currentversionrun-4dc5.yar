rule TTP_XOR_QUAD_CurrentVersionRun_4dc5 {
  strings:
    $key_4dc5 = { 1e aa [2] 3a a4 [2] 11 88 [2] 3f aa [2] 2b b1 [2] 24 ab [2] 3a b6 [2] 38 b7 [2] 23 b1 [2] 3f b6 [2] 23 99 }

  condition:
    any of them
}