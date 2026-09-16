rule TTP_XOR_QUAD_CurrentVersionRun_7dc2 {
  strings:
    $key_7dc2 = { 2e ad [2] 0a a3 [2] 21 8f [2] 0f ad [2] 1b b6 [2] 14 ac [2] 0a b1 [2] 08 b0 [2] 13 b6 [2] 0f b1 [2] 13 9e }

  condition:
    any of them
}