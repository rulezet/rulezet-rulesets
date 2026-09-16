rule TTP_XOR_QUAD_CurrentVersionRun_66c6 {
  strings:
    $key_66c6 = { 35 a9 [2] 11 a7 [2] 3a 8b [2] 14 a9 [2] 00 b2 [2] 0f a8 [2] 11 b5 [2] 13 b4 [2] 08 b2 [2] 14 b5 [2] 08 9a }

  condition:
    any of them
}