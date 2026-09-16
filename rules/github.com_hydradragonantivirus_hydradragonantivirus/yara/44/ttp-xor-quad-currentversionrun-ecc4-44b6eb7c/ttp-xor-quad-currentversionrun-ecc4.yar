rule TTP_XOR_QUAD_CurrentVersionRun_ecc4 {
  strings:
    $key_ecc4 = { bf ab [2] 9b a5 [2] b0 89 [2] 9e ab [2] 8a b0 [2] 85 aa [2] 9b b7 [2] 99 b6 [2] 82 b0 [2] 9e b7 [2] 82 98 }

  condition:
    any of them
}