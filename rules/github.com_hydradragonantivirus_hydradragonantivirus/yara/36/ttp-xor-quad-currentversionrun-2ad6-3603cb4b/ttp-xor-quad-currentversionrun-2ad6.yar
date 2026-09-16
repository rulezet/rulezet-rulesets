rule TTP_XOR_QUAD_CurrentVersionRun_2ad6 {
  strings:
    $key_2ad6 = { 79 b9 [2] 5d b7 [2] 76 9b [2] 58 b9 [2] 4c a2 [2] 43 b8 [2] 5d a5 [2] 5f a4 [2] 44 a2 [2] 58 a5 [2] 44 8a }

  condition:
    any of them
}