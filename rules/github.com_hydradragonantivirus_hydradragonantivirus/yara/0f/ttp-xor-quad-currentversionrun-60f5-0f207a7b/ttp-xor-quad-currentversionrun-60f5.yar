rule TTP_XOR_QUAD_CurrentVersionRun_60f5 {
  strings:
    $key_60f5 = { 33 9a [2] 17 94 [2] 3c b8 [2] 12 9a [2] 06 81 [2] 09 9b [2] 17 86 [2] 15 87 [2] 0e 81 [2] 12 86 [2] 0e a9 }

  condition:
    any of them
}