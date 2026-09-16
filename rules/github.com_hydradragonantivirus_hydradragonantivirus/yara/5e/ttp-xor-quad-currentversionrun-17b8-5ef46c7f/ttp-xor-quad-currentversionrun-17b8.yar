rule TTP_XOR_QUAD_CurrentVersionRun_17b8 {
  strings:
    $key_17b8 = { 44 d7 [2] 60 d9 [2] 4b f5 [2] 65 d7 [2] 71 cc [2] 7e d6 [2] 60 cb [2] 62 ca [2] 79 cc [2] 65 cb [2] 79 e4 }

  condition:
    any of them
}