rule TTP_XOR_QUAD_CurrentVersionRun_f9d6 {
  strings:
    $key_f9d6 = { aa b9 [2] 8e b7 [2] a5 9b [2] 8b b9 [2] 9f a2 [2] 90 b8 [2] 8e a5 [2] 8c a4 [2] 97 a2 [2] 8b a5 [2] 97 8a }

  condition:
    any of them
}