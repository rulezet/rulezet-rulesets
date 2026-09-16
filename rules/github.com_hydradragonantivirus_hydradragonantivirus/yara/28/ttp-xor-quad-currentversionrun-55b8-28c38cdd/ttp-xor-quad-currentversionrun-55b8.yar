rule TTP_XOR_QUAD_CurrentVersionRun_55b8 {
  strings:
    $key_55b8 = { 06 d7 [2] 22 d9 [2] 09 f5 [2] 27 d7 [2] 33 cc [2] 3c d6 [2] 22 cb [2] 20 ca [2] 3b cc [2] 27 cb [2] 3b e4 }

  condition:
    any of them
}