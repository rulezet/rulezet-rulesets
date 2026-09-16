rule TTP_XOR_QUAD_CurrentVersionRun_04b8 {
  strings:
    $key_04b8 = { 57 d7 [2] 73 d9 [2] 58 f5 [2] 76 d7 [2] 62 cc [2] 6d d6 [2] 73 cb [2] 71 ca [2] 6a cc [2] 76 cb [2] 6a e4 }

  condition:
    any of them
}