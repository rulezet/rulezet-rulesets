rule TTP_XOR_QUAD_CurrentVersionRun_1cc6 {
  strings:
    $key_1cc6 = { 4f a9 [2] 6b a7 [2] 40 8b [2] 6e a9 [2] 7a b2 [2] 75 a8 [2] 6b b5 [2] 69 b4 [2] 72 b2 [2] 6e b5 [2] 72 9a }

  condition:
    any of them
}