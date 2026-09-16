rule TTP_XOR_QUAD_CurrentVersionRun_01b8 {
  strings:
    $key_01b8 = { 52 d7 [2] 76 d9 [2] 5d f5 [2] 73 d7 [2] 67 cc [2] 68 d6 [2] 76 cb [2] 74 ca [2] 6f cc [2] 73 cb [2] 6f e4 }

  condition:
    any of them
}