rule TTP_XOR_QUAD_CurrentVersionRun_49a5 {
  strings:
    $key_49a5 = { 1a ca [2] 3e c4 [2] 15 e8 [2] 3b ca [2] 2f d1 [2] 20 cb [2] 3e d6 [2] 3c d7 [2] 27 d1 [2] 3b d6 [2] 27 f9 }

  condition:
    any of them
}