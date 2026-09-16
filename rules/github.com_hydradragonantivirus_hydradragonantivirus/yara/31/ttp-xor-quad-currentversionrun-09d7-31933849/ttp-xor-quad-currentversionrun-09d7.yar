rule TTP_XOR_QUAD_CurrentVersionRun_09d7 {
  strings:
    $key_09d7 = { 5a b8 [2] 7e b6 [2] 55 9a [2] 7b b8 [2] 6f a3 [2] 60 b9 [2] 7e a4 [2] 7c a5 [2] 67 a3 [2] 7b a4 [2] 67 8b }

  condition:
    any of them
}