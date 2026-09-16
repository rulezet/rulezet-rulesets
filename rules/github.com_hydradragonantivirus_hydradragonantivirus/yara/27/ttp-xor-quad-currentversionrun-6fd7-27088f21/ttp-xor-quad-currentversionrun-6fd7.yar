rule TTP_XOR_QUAD_CurrentVersionRun_6fd7 {
  strings:
    $key_6fd7 = { 3c b8 [2] 18 b6 [2] 33 9a [2] 1d b8 [2] 09 a3 [2] 06 b9 [2] 18 a4 [2] 1a a5 [2] 01 a3 [2] 1d a4 [2] 01 8b }

  condition:
    any of them
}