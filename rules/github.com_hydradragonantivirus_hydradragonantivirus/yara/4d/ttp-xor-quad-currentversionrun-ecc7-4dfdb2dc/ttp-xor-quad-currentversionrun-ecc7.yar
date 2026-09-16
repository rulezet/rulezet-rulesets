rule TTP_XOR_QUAD_CurrentVersionRun_ecc7 {
  strings:
    $key_ecc7 = { bf a8 [2] 9b a6 [2] b0 8a [2] 9e a8 [2] 8a b3 [2] 85 a9 [2] 9b b4 [2] 99 b5 [2] 82 b3 [2] 9e b4 [2] 82 9b }

  condition:
    any of them
}