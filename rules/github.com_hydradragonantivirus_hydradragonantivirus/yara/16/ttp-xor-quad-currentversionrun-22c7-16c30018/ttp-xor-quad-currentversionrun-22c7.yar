rule TTP_XOR_QUAD_CurrentVersionRun_22c7 {
  strings:
    $key_22c7 = { 71 a8 [2] 55 a6 [2] 7e 8a [2] 50 a8 [2] 44 b3 [2] 4b a9 [2] 55 b4 [2] 57 b5 [2] 4c b3 [2] 50 b4 [2] 4c 9b }

  condition:
    any of them
}