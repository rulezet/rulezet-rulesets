rule TTP_XOR_QUAD_CurrentVersionRun_22b8 {
  strings:
    $key_22b8 = { 71 d7 [2] 55 d9 [2] 7e f5 [2] 50 d7 [2] 44 cc [2] 4b d6 [2] 55 cb [2] 57 ca [2] 4c cc [2] 50 cb [2] 4c e4 }

  condition:
    any of them
}