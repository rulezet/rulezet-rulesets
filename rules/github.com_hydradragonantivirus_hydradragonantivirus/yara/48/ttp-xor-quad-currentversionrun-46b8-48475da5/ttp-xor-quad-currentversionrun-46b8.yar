rule TTP_XOR_QUAD_CurrentVersionRun_46b8 {
  strings:
    $key_46b8 = { 15 d7 [2] 31 d9 [2] 1a f5 [2] 34 d7 [2] 20 cc [2] 2f d6 [2] 31 cb [2] 33 ca [2] 28 cc [2] 34 cb [2] 28 e4 }

  condition:
    any of them
}