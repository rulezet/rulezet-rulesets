rule TTP_XOR_QUAD_CurrentVersionRun_64d7 {
  strings:
    $key_64d7 = { 37 b8 [2] 13 b6 [2] 38 9a [2] 16 b8 [2] 02 a3 [2] 0d b9 [2] 13 a4 [2] 11 a5 [2] 0a a3 [2] 16 a4 [2] 0a 8b }

  condition:
    any of them
}