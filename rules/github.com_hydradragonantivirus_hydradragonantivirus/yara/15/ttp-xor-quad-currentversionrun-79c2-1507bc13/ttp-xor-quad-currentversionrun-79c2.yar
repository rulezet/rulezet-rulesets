rule TTP_XOR_QUAD_CurrentVersionRun_79c2 {
  strings:
    $key_79c2 = { 2a ad [2] 0e a3 [2] 25 8f [2] 0b ad [2] 1f b6 [2] 10 ac [2] 0e b1 [2] 0c b0 [2] 17 b6 [2] 0b b1 [2] 17 9e }

  condition:
    any of them
}