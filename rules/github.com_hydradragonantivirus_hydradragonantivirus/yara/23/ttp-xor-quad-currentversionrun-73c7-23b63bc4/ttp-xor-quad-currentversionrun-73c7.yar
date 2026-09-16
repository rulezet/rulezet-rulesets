rule TTP_XOR_QUAD_CurrentVersionRun_73c7 {
  strings:
    $key_73c7 = { 20 a8 [2] 04 a6 [2] 2f 8a [2] 01 a8 [2] 15 b3 [2] 1a a9 [2] 04 b4 [2] 06 b5 [2] 1d b3 [2] 01 b4 [2] 1d 9b }

  condition:
    any of them
}