rule TTP_XOR_QUAD_CurrentVersionRun_67b8 {
  strings:
    $key_67b8 = { 34 d7 [2] 10 d9 [2] 3b f5 [2] 15 d7 [2] 01 cc [2] 0e d6 [2] 10 cb [2] 12 ca [2] 09 cc [2] 15 cb [2] 09 e4 }

  condition:
    any of them
}