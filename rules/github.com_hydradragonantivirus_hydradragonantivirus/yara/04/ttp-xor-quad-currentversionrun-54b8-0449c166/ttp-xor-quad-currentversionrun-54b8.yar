rule TTP_XOR_QUAD_CurrentVersionRun_54b8 {
  strings:
    $key_54b8 = { 07 d7 [2] 23 d9 [2] 08 f5 [2] 26 d7 [2] 32 cc [2] 3d d6 [2] 23 cb [2] 21 ca [2] 3a cc [2] 26 cb [2] 3a e4 }

  condition:
    any of them
}