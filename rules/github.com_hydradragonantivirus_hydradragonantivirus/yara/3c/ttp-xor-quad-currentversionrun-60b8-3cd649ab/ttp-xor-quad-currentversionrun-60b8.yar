rule TTP_XOR_QUAD_CurrentVersionRun_60b8 {
  strings:
    $key_60b8 = { 33 d7 [2] 17 d9 [2] 3c f5 [2] 12 d7 [2] 06 cc [2] 09 d6 [2] 17 cb [2] 15 ca [2] 0e cc [2] 12 cb [2] 0e e4 }

  condition:
    any of them
}