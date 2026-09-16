rule TTP_XOR_QUAD_CurrentVersionRun_2cc2 {
  strings:
    $key_2cc2 = { 7f ad [2] 5b a3 [2] 70 8f [2] 5e ad [2] 4a b6 [2] 45 ac [2] 5b b1 [2] 59 b0 [2] 42 b6 [2] 5e b1 [2] 42 9e }

  condition:
    any of them
}