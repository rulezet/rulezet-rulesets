rule TTP_XOR_QUAD_CurrentVersionRun_07b8 {
  strings:
    $key_07b8 = { 54 d7 [2] 70 d9 [2] 5b f5 [2] 75 d7 [2] 61 cc [2] 6e d6 [2] 70 cb [2] 72 ca [2] 69 cc [2] 75 cb [2] 69 e4 }

  condition:
    any of them
}