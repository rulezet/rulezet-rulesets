rule TTP_XOR_QUAD_CurrentVersionRun_39d7 {
  strings:
    $key_39d7 = { 6a b8 [2] 4e b6 [2] 65 9a [2] 4b b8 [2] 5f a3 [2] 50 b9 [2] 4e a4 [2] 4c a5 [2] 57 a3 [2] 4b a4 [2] 57 8b }

  condition:
    any of them
}