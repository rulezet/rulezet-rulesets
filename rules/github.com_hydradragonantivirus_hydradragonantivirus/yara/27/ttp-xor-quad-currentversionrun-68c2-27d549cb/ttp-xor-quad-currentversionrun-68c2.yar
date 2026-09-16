rule TTP_XOR_QUAD_CurrentVersionRun_68c2 {
  strings:
    $key_68c2 = { 3b ad [2] 1f a3 [2] 34 8f [2] 1a ad [2] 0e b6 [2] 01 ac [2] 1f b1 [2] 1d b0 [2] 06 b6 [2] 1a b1 [2] 06 9e }

  condition:
    any of them
}