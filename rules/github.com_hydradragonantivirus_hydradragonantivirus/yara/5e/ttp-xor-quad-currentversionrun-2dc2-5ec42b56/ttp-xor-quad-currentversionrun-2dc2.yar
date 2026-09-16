rule TTP_XOR_QUAD_CurrentVersionRun_2dc2 {
  strings:
    $key_2dc2 = { 7e ad [2] 5a a3 [2] 71 8f [2] 5f ad [2] 4b b6 [2] 44 ac [2] 5a b1 [2] 58 b0 [2] 43 b6 [2] 5f b1 [2] 43 9e }

  condition:
    any of them
}