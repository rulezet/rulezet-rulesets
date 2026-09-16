rule TTP_XOR_QUAD_CurrentVersionRun_4cc2 {
  strings:
    $key_4cc2 = { 1f ad [2] 3b a3 [2] 10 8f [2] 3e ad [2] 2a b6 [2] 25 ac [2] 3b b1 [2] 39 b0 [2] 22 b6 [2] 3e b1 [2] 22 9e }

  condition:
    any of them
}