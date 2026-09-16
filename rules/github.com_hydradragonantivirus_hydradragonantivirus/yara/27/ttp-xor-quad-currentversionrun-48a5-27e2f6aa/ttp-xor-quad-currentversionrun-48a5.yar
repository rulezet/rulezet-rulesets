rule TTP_XOR_QUAD_CurrentVersionRun_48a5 {
  strings:
    $key_48a5 = { 1b ca [2] 3f c4 [2] 14 e8 [2] 3a ca [2] 2e d1 [2] 21 cb [2] 3f d6 [2] 3d d7 [2] 26 d1 [2] 3a d6 [2] 26 f9 }

  condition:
    any of them
}