rule TTP_XOR_QUAD_CurrentVersionRun_1cc2 {
  strings:
    $key_1cc2 = { 4f ad [2] 6b a3 [2] 40 8f [2] 6e ad [2] 7a b6 [2] 75 ac [2] 6b b1 [2] 69 b0 [2] 72 b6 [2] 6e b1 [2] 72 9e }

  condition:
    any of them
}