rule TTP_XOR_QUAD_CurrentVersionRun_31c6 {
  strings:
    $key_31c6 = { 62 a9 [2] 46 a7 [2] 6d 8b [2] 43 a9 [2] 57 b2 [2] 58 a8 [2] 46 b5 [2] 44 b4 [2] 5f b2 [2] 43 b5 [2] 5f 9a }

  condition:
    any of them
}