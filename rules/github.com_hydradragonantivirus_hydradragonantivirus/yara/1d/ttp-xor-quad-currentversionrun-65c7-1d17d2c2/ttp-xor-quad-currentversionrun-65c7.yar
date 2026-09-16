rule TTP_XOR_QUAD_CurrentVersionRun_65c7 {
  strings:
    $key_65c7 = { 36 a8 [2] 12 a6 [2] 39 8a [2] 17 a8 [2] 03 b3 [2] 0c a9 [2] 12 b4 [2] 10 b5 [2] 0b b3 [2] 17 b4 [2] 0b 9b }

  condition:
    any of them
}