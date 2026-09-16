rule TTP_XOR_QUAD_CurrentVersionRun_29d7 {
  strings:
    $key_29d7 = { 7a b8 [2] 5e b6 [2] 75 9a [2] 5b b8 [2] 4f a3 [2] 40 b9 [2] 5e a4 [2] 5c a5 [2] 47 a3 [2] 5b a4 [2] 47 8b }

  condition:
    any of them
}