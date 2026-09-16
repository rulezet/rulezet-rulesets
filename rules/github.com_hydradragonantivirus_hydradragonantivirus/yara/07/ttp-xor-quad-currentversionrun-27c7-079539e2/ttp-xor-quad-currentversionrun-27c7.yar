rule TTP_XOR_QUAD_CurrentVersionRun_27c7 {
  strings:
    $key_27c7 = { 74 a8 [2] 50 a6 [2] 7b 8a [2] 55 a8 [2] 41 b3 [2] 4e a9 [2] 50 b4 [2] 52 b5 [2] 49 b3 [2] 55 b4 [2] 49 9b }

  condition:
    any of them
}