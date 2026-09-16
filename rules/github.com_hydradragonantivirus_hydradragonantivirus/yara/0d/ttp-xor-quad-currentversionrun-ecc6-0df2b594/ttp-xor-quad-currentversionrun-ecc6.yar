rule TTP_XOR_QUAD_CurrentVersionRun_ecc6 {
  strings:
    $key_ecc6 = { bf a9 [2] 9b a7 [2] b0 8b [2] 9e a9 [2] 8a b2 [2] 85 a8 [2] 9b b5 [2] 99 b4 [2] 82 b2 [2] 9e b5 [2] 82 9a }

  condition:
    any of them
}