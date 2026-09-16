rule TTP_XOR_QUAD_CurrentVersionRun_78c2 {
  strings:
    $key_78c2 = { 2b ad [2] 0f a3 [2] 24 8f [2] 0a ad [2] 1e b6 [2] 11 ac [2] 0f b1 [2] 0d b0 [2] 16 b6 [2] 0a b1 [2] 16 9e }

  condition:
    any of them
}