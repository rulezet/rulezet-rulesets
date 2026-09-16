rule TTP_XOR_QUAD_CurrentVersionRun_69c2 {
  strings:
    $key_69c2 = { 3a ad [2] 1e a3 [2] 35 8f [2] 1b ad [2] 0f b6 [2] 00 ac [2] 1e b1 [2] 1c b0 [2] 07 b6 [2] 1b b1 [2] 07 9e }

  condition:
    any of them
}