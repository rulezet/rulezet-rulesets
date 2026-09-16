rule TTP_XOR_QUAD_CurrentVersionRun_49c2 {
  strings:
    $key_49c2 = { 1a ad [2] 3e a3 [2] 15 8f [2] 3b ad [2] 2f b6 [2] 20 ac [2] 3e b1 [2] 3c b0 [2] 27 b6 [2] 3b b1 [2] 27 9e }

  condition:
    any of them
}