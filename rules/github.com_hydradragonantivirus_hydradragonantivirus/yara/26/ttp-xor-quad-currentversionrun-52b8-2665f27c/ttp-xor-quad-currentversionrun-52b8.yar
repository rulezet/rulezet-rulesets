rule TTP_XOR_QUAD_CurrentVersionRun_52b8 {
  strings:
    $key_52b8 = { 01 d7 [2] 25 d9 [2] 0e f5 [2] 20 d7 [2] 34 cc [2] 3b d6 [2] 25 cb [2] 27 ca [2] 3c cc [2] 20 cb [2] 3c e4 }

  condition:
    any of them
}