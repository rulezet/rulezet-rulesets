rule TTP_XOR_QUAD_CurrentVersionRun_08c2 {
  strings:
    $key_08c2 = { 5b ad [2] 7f a3 [2] 54 8f [2] 7a ad [2] 6e b6 [2] 61 ac [2] 7f b1 [2] 7d b0 [2] 66 b6 [2] 7a b1 [2] 66 9e }

  condition:
    any of them
}