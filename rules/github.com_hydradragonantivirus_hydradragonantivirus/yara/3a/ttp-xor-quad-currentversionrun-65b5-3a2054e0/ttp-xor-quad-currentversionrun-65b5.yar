rule TTP_XOR_QUAD_CurrentVersionRun_65b5 {
  strings:
    $key_65b5 = { 36 da [2] 12 d4 [2] 39 f8 [2] 17 da [2] 03 c1 [2] 0c db [2] 12 c6 [2] 10 c7 [2] 0b c1 [2] 17 c6 [2] 0b e9 }

  condition:
    any of them
}