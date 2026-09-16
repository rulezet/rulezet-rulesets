rule TTP_XOR_QUAD_CurrentVersionRun_7dc5 {
  strings:
    $key_7dc5 = { 2e aa [2] 0a a4 [2] 21 88 [2] 0f aa [2] 1b b1 [2] 14 ab [2] 0a b6 [2] 08 b7 [2] 13 b1 [2] 0f b6 [2] 13 99 }

  condition:
    any of them
}