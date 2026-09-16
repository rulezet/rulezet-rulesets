rule TTP_XOR_QUAD_CurrentVersionRun_41d7 {
  strings:
    $key_41d7 = { 12 b8 [2] 36 b6 [2] 1d 9a [2] 33 b8 [2] 27 a3 [2] 28 b9 [2] 36 a4 [2] 34 a5 [2] 2f a3 [2] 33 a4 [2] 2f 8b }

  condition:
    any of them
}