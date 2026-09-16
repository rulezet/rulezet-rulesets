rule TTP_XOR_QUAD_CurrentVersionRun_03c6 {
  strings:
    $key_03c6 = { 50 a9 [2] 74 a7 [2] 5f 8b [2] 71 a9 [2] 65 b2 [2] 6a a8 [2] 74 b5 [2] 76 b4 [2] 6d b2 [2] 71 b5 [2] 6d 9a }

  condition:
    any of them
}