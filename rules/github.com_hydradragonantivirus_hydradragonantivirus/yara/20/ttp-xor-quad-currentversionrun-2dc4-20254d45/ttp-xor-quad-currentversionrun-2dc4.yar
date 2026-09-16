rule TTP_XOR_QUAD_CurrentVersionRun_2dc4 {
  strings:
    $key_2dc4 = { 7e ab [2] 5a a5 [2] 71 89 [2] 5f ab [2] 4b b0 [2] 44 aa [2] 5a b7 [2] 58 b6 [2] 43 b0 [2] 5f b7 [2] 43 98 }

  condition:
    any of them
}