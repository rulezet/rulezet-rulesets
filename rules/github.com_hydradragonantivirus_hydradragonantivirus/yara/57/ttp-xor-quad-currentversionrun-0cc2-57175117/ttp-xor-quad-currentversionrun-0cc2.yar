rule TTP_XOR_QUAD_CurrentVersionRun_0cc2 {
  strings:
    $key_0cc2 = { 5f ad [2] 7b a3 [2] 50 8f [2] 7e ad [2] 6a b6 [2] 65 ac [2] 7b b1 [2] 79 b0 [2] 62 b6 [2] 7e b1 [2] 62 9e }

  condition:
    any of them
}