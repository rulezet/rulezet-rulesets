rule TTP_XOR_QUAD_CurrentVersionRun_62b8 {
  strings:
    $key_62b8 = { 31 d7 [2] 15 d9 [2] 3e f5 [2] 10 d7 [2] 04 cc [2] 0b d6 [2] 15 cb [2] 17 ca [2] 0c cc [2] 10 cb [2] 0c e4 }

  condition:
    any of them
}