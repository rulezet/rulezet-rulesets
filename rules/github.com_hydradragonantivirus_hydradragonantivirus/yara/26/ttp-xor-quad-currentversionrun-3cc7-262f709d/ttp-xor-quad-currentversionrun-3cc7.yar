rule TTP_XOR_QUAD_CurrentVersionRun_3cc7 {
  strings:
    $key_3cc7 = { 6f a8 [2] 4b a6 [2] 60 8a [2] 4e a8 [2] 5a b3 [2] 55 a9 [2] 4b b4 [2] 49 b5 [2] 52 b3 [2] 4e b4 [2] 52 9b }

  condition:
    any of them
}