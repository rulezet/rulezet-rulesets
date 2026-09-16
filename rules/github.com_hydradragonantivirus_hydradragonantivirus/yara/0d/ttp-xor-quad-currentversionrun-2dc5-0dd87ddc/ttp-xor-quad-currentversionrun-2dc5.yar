rule TTP_XOR_QUAD_CurrentVersionRun_2dc5 {
  strings:
    $key_2dc5 = { 7e aa [2] 5a a4 [2] 71 88 [2] 5f aa [2] 4b b1 [2] 44 ab [2] 5a b6 [2] 58 b7 [2] 43 b1 [2] 5f b6 [2] 43 99 }

  condition:
    any of them
}