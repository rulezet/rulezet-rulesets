rule TTP_XOR_QUAD_CurrentVersionRun_19c2 {
  strings:
    $key_19c2 = { 4a ad [2] 6e a3 [2] 45 8f [2] 6b ad [2] 7f b6 [2] 70 ac [2] 6e b1 [2] 6c b0 [2] 77 b6 [2] 6b b1 [2] 77 9e }

  condition:
    any of them
}