rule TTP_XOR_QUAD_CurrentVersionRun_2cc5 {
  strings:
    $key_2cc5 = { 7f aa [2] 5b a4 [2] 70 88 [2] 5e aa [2] 4a b1 [2] 45 ab [2] 5b b6 [2] 59 b7 [2] 42 b1 [2] 5e b6 [2] 42 99 }

  condition:
    any of them
}