rule TTP_XOR_QUAD_CurrentVersionRun_47c7 {
  strings:
    $key_47c7 = { 14 a8 [2] 30 a6 [2] 1b 8a [2] 35 a8 [2] 21 b3 [2] 2e a9 [2] 30 b4 [2] 32 b5 [2] 29 b3 [2] 35 b4 [2] 29 9b }

  condition:
    any of them
}