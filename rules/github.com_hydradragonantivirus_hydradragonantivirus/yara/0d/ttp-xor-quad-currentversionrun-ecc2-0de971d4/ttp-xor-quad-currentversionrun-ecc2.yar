rule TTP_XOR_QUAD_CurrentVersionRun_ecc2 {
  strings:
    $key_ecc2 = { bf ad [2] 9b a3 [2] b0 8f [2] 9e ad [2] 8a b6 [2] 85 ac [2] 9b b1 [2] 99 b0 [2] 82 b6 [2] 9e b1 [2] 82 9e }

  condition:
    any of them
}