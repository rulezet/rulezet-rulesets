rule TTP_XOR_QUAD_CurrentVersionRun_09c2 {
  strings:
    $key_09c2 = { 5a ad [2] 7e a3 [2] 55 8f [2] 7b ad [2] 6f b6 [2] 60 ac [2] 7e b1 [2] 7c b0 [2] 67 b6 [2] 7b b1 [2] 67 9e }

  condition:
    any of them
}