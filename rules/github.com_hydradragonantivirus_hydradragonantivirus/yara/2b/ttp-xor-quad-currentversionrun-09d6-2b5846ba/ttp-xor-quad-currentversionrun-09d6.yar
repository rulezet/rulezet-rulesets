rule TTP_XOR_QUAD_CurrentVersionRun_09d6 {
  strings:
    $key_09d6 = { 5a b9 [2] 7e b7 [2] 55 9b [2] 7b b9 [2] 6f a2 [2] 60 b8 [2] 7e a5 [2] 7c a4 [2] 67 a2 [2] 7b a5 [2] 67 8a }

  condition:
    any of them
}