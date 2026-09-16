rule TTP_XOR_QUAD_CurrentVersionRun_41d6 {
  strings:
    $key_41d6 = { 12 b9 [2] 36 b7 [2] 1d 9b [2] 33 b9 [2] 27 a2 [2] 28 b8 [2] 36 a5 [2] 34 a4 [2] 2f a2 [2] 33 a5 [2] 2f 8a }

  condition:
    any of them
}