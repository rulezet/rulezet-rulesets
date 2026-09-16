rule TTP_XOR_QUAD_CurrentVersionRun_31b8 {
  strings:
    $key_31b8 = { 62 d7 [2] 46 d9 [2] 6d f5 [2] 43 d7 [2] 57 cc [2] 58 d6 [2] 46 cb [2] 44 ca [2] 5f cc [2] 43 cb [2] 5f e4 }

  condition:
    any of them
}