rule TTP_XOR_QUAD_CurrentVersionRun_dab8 {
  strings:
    $key_dab8 = { 89 d7 [2] ad d9 [2] 86 f5 [2] a8 d7 [2] bc cc [2] b3 d6 [2] ad cb [2] af ca [2] b4 cc [2] a8 cb [2] b4 e4 }

  condition:
    any of them
}