rule TTP_XOR_QUAD_CurrentVersionRun_31d6 {
  strings:
    $key_31d6 = { 62 b9 [2] 46 b7 [2] 6d 9b [2] 43 b9 [2] 57 a2 [2] 58 b8 [2] 46 a5 [2] 44 a4 [2] 5f a2 [2] 43 a5 [2] 5f 8a }

  condition:
    any of them
}