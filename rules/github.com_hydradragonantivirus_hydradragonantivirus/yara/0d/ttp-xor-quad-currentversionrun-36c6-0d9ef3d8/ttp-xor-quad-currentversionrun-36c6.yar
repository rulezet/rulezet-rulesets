rule TTP_XOR_QUAD_CurrentVersionRun_36c6 {
  strings:
    $key_36c6 = { 65 a9 [2] 41 a7 [2] 6a 8b [2] 44 a9 [2] 50 b2 [2] 5f a8 [2] 41 b5 [2] 43 b4 [2] 58 b2 [2] 44 b5 [2] 58 9a }

  condition:
    any of them
}