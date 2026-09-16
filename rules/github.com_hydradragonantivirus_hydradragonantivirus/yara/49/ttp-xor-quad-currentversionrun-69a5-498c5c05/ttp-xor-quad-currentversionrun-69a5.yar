rule TTP_XOR_QUAD_CurrentVersionRun_69a5 {
  strings:
    $key_69a5 = { 3a ca [2] 1e c4 [2] 35 e8 [2] 1b ca [2] 0f d1 [2] 00 cb [2] 1e d6 [2] 1c d7 [2] 07 d1 [2] 1b d6 [2] 07 f9 }

  condition:
    any of them
}