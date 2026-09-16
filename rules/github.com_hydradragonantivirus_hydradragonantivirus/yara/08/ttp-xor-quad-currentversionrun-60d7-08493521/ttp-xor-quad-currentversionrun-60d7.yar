rule TTP_XOR_QUAD_CurrentVersionRun_60d7 {
  strings:
    $key_60d7 = { 33 b8 [2] 17 b6 [2] 3c 9a [2] 12 b8 [2] 06 a3 [2] 09 b9 [2] 17 a4 [2] 15 a5 [2] 0e a3 [2] 12 a4 [2] 0e 8b }

  condition:
    any of them
}