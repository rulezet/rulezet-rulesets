rule TTP_XOR_QUAD_CurrentVersionRun_5ac6 {
  strings:
    $key_5ac6 = { 09 a9 [2] 2d a7 [2] 06 8b [2] 28 a9 [2] 3c b2 [2] 33 a8 [2] 2d b5 [2] 2f b4 [2] 34 b2 [2] 28 b5 [2] 34 9a }

  condition:
    any of them
}