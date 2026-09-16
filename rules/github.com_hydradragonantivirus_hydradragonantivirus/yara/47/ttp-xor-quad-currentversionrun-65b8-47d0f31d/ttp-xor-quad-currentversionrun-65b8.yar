rule TTP_XOR_QUAD_CurrentVersionRun_65b8 {
  strings:
    $key_65b8 = { 36 d7 [2] 12 d9 [2] 39 f5 [2] 17 d7 [2] 03 cc [2] 0c d6 [2] 12 cb [2] 10 ca [2] 0b cc [2] 17 cb [2] 0b e4 }

  condition:
    any of them
}