rule TTP_XOR_QUAD_CurrentVersionRun_fca5 {
  strings:
    $key_fca5 = { af ca [2] 8b c4 [2] a0 e8 [2] 8e ca [2] 9a d1 [2] 95 cb [2] 8b d6 [2] 89 d7 [2] 92 d1 [2] 8e d6 [2] 92 f9 }

  condition:
    any of them
}