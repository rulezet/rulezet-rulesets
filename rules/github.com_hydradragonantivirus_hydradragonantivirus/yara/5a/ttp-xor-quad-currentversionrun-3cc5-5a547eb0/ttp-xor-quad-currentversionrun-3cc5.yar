rule TTP_XOR_QUAD_CurrentVersionRun_3cc5 {
  strings:
    $key_3cc5 = { 6f aa [2] 4b a4 [2] 60 88 [2] 4e aa [2] 5a b1 [2] 55 ab [2] 4b b6 [2] 49 b7 [2] 52 b1 [2] 4e b6 [2] 52 99 }

  condition:
    any of them
}