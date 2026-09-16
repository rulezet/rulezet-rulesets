rule TTP_XOR_QUAD_CurrentVersionRun_77c7 {
  strings:
    $key_77c7 = { 24 a8 [2] 00 a6 [2] 2b 8a [2] 05 a8 [2] 11 b3 [2] 1e a9 [2] 00 b4 [2] 02 b5 [2] 19 b3 [2] 05 b4 [2] 19 9b }

  condition:
    any of them
}