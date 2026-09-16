rule TTP_XOR_QUAD_CurrentVersionRun_65b4 {
  strings:
    $key_65b4 = { 36 db [2] 12 d5 [2] 39 f9 [2] 17 db [2] 03 c0 [2] 0c da [2] 12 c7 [2] 10 c6 [2] 0b c0 [2] 17 c7 [2] 0b e8 }

  condition:
    any of them
}