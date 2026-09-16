rule TTP_XOR_QUAD_CurrentVersionRun_64d6 {
  strings:
    $key_64d6 = { 37 b9 [2] 13 b7 [2] 38 9b [2] 16 b9 [2] 02 a2 [2] 0d b8 [2] 13 a5 [2] 11 a4 [2] 0a a2 [2] 16 a5 [2] 0a 8a }

  condition:
    any of them
}