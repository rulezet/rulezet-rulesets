rule TTP_XOR_QUAD_CurrentVersionRun_5dc4 {
  strings:
    $key_5dc4 = { 0e ab [2] 2a a5 [2] 01 89 [2] 2f ab [2] 3b b0 [2] 34 aa [2] 2a b7 [2] 28 b6 [2] 33 b0 [2] 2f b7 [2] 33 98 }

  condition:
    any of them
}