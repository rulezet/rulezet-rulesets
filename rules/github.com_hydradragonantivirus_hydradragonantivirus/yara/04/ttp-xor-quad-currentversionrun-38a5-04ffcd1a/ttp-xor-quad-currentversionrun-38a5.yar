rule TTP_XOR_QUAD_CurrentVersionRun_38a5 {
  strings:
    $key_38a5 = { 6b ca [2] 4f c4 [2] 64 e8 [2] 4a ca [2] 5e d1 [2] 51 cb [2] 4f d6 [2] 4d d7 [2] 56 d1 [2] 4a d6 [2] 56 f9 }

  condition:
    any of them
}