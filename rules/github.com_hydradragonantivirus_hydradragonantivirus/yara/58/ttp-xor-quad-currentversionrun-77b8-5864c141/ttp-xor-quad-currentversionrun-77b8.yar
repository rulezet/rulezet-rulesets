rule TTP_XOR_QUAD_CurrentVersionRun_77b8 {
  strings:
    $key_77b8 = { 24 d7 [2] 00 d9 [2] 2b f5 [2] 05 d7 [2] 11 cc [2] 1e d6 [2] 00 cb [2] 02 ca [2] 19 cc [2] 05 cb [2] 19 e4 }

  condition:
    any of them
}