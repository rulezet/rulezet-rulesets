rule TTP_XOR_QUAD_CurrentVersionRun_1586 {
  strings:
    $key_1586 = { 46 e9 [2] 62 e7 [2] 49 cb [2] 67 e9 [2] 73 f2 [2] 7c e8 [2] 62 f5 [2] 60 f4 [2] 7b f2 [2] 67 f5 [2] 7b da }

  condition:
    any of them
}