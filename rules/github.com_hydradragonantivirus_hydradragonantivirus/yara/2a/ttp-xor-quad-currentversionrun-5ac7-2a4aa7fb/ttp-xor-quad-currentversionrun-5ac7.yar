rule TTP_XOR_QUAD_CurrentVersionRun_5ac7 {
  strings:
    $key_5ac7 = { 09 a8 [2] 2d a6 [2] 06 8a [2] 28 a8 [2] 3c b3 [2] 33 a9 [2] 2d b4 [2] 2f b5 [2] 34 b3 [2] 28 b4 [2] 34 9b }

  condition:
    any of them
}