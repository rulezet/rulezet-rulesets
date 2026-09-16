rule TTP_XOR_QUAD_CurrentVersionRun_66c7 {
  strings:
    $key_66c7 = { 35 a8 [2] 11 a6 [2] 3a 8a [2] 14 a8 [2] 00 b3 [2] 0f a9 [2] 11 b4 [2] 13 b5 [2] 08 b3 [2] 14 b4 [2] 08 9b }

  condition:
    any of them
}