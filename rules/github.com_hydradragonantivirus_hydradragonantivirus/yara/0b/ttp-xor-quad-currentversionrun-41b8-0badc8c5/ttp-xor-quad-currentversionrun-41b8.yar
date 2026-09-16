rule TTP_XOR_QUAD_CurrentVersionRun_41b8 {
  strings:
    $key_41b8 = { 12 d7 [2] 36 d9 [2] 1d f5 [2] 33 d7 [2] 27 cc [2] 28 d6 [2] 36 cb [2] 34 ca [2] 2f cc [2] 33 cb [2] 2f e4 }

  condition:
    any of them
}