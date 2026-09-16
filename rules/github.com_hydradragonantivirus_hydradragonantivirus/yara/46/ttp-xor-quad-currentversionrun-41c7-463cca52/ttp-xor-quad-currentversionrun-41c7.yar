rule TTP_XOR_QUAD_CurrentVersionRun_41c7 {
  strings:
    $key_41c7 = { 12 a8 [2] 36 a6 [2] 1d 8a [2] 33 a8 [2] 27 b3 [2] 28 a9 [2] 36 b4 [2] 34 b5 [2] 2f b3 [2] 33 b4 [2] 2f 9b }

  condition:
    any of them
}