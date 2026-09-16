rule TTP_XOR_QUAD_CurrentVersionRun_f8a5 {
  strings:
    $key_f8a5 = { ab ca [2] 8f c4 [2] a4 e8 [2] 8a ca [2] 9e d1 [2] 91 cb [2] 8f d6 [2] 8d d7 [2] 96 d1 [2] 8a d6 [2] 96 f9 }

  condition:
    any of them
}