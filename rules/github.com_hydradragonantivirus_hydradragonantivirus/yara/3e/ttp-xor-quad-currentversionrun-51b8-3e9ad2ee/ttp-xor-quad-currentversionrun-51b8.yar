rule TTP_XOR_QUAD_CurrentVersionRun_51b8 {
  strings:
    $key_51b8 = { 02 d7 [2] 26 d9 [2] 0d f5 [2] 23 d7 [2] 37 cc [2] 38 d6 [2] 26 cb [2] 24 ca [2] 3f cc [2] 23 cb [2] 3f e4 }

  condition:
    any of them
}