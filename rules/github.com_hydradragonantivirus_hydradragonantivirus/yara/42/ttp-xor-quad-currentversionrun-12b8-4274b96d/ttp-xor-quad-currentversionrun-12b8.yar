rule TTP_XOR_QUAD_CurrentVersionRun_12b8 {
  strings:
    $key_12b8 = { 41 d7 [2] 65 d9 [2] 4e f5 [2] 60 d7 [2] 74 cc [2] 7b d6 [2] 65 cb [2] 67 ca [2] 7c cc [2] 60 cb [2] 7c e4 }

  condition:
    any of them
}