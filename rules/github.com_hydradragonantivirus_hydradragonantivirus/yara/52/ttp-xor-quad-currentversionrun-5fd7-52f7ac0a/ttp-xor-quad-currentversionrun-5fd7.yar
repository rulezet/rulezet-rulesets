rule TTP_XOR_QUAD_CurrentVersionRun_5fd7 {
  strings:
    $key_5fd7 = { 0c b8 [2] 28 b6 [2] 03 9a [2] 2d b8 [2] 39 a3 [2] 36 b9 [2] 28 a4 [2] 2a a5 [2] 31 a3 [2] 2d a4 [2] 31 8b }

  condition:
    any of them
}