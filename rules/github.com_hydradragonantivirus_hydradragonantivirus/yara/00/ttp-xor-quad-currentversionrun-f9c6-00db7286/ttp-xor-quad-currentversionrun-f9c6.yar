rule TTP_XOR_QUAD_CurrentVersionRun_f9c6 {
  strings:
    $key_f9c6 = { aa a9 [2] 8e a7 [2] a5 8b [2] 8b a9 [2] 9f b2 [2] 90 a8 [2] 8e b5 [2] 8c b4 [2] 97 b2 [2] 8b b5 [2] 97 9a }

  condition:
    any of them
}