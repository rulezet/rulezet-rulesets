rule TTP_XOR_QUAD_CurrentVersionRun_17c7 {
  strings:
    $key_17c7 = { 44 a8 [2] 60 a6 [2] 4b 8a [2] 65 a8 [2] 71 b3 [2] 7e a9 [2] 60 b4 [2] 62 b5 [2] 79 b3 [2] 65 b4 [2] 79 9b }

  condition:
    any of them
}