rule TTP_XOR_QUAD_CurrentVersionRun_2ac7 {
  strings:
    $key_2ac7 = { 79 a8 [2] 5d a6 [2] 76 8a [2] 58 a8 [2] 4c b3 [2] 43 a9 [2] 5d b4 [2] 5f b5 [2] 44 b3 [2] 58 b4 [2] 44 9b }

  condition:
    any of them
}