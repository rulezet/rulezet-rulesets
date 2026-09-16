rule TTP_XOR_QUAD_CurrentVersionRun_4dc2 {
  strings:
    $key_4dc2 = { 1e ad [2] 3a a3 [2] 11 8f [2] 3f ad [2] 2b b6 [2] 24 ac [2] 3a b1 [2] 38 b0 [2] 23 b6 [2] 3f b1 [2] 23 9e }

  condition:
    any of them
}