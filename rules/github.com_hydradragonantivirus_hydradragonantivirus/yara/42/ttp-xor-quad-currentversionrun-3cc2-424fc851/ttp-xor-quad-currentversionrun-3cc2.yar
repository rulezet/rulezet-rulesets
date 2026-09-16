rule TTP_XOR_QUAD_CurrentVersionRun_3cc2 {
  strings:
    $key_3cc2 = { 6f ad [2] 4b a3 [2] 60 8f [2] 4e ad [2] 5a b6 [2] 55 ac [2] 4b b1 [2] 49 b0 [2] 52 b6 [2] 4e b1 [2] 52 9e }

  condition:
    any of them
}