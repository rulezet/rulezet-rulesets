rule TTP_XOR_QUAD_CurrentVersionRun_07c7 {
  strings:
    $key_07c7 = { 54 a8 [2] 70 a6 [2] 5b 8a [2] 75 a8 [2] 61 b3 [2] 6e a9 [2] 70 b4 [2] 72 b5 [2] 69 b3 [2] 75 b4 [2] 69 9b }

  condition:
    any of them
}