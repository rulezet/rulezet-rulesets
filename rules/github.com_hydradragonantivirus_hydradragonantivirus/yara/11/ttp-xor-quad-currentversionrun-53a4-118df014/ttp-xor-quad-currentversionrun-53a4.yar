rule TTP_XOR_QUAD_CurrentVersionRun_53a4 {
  strings:
    $key_53a4 = { 00 cb [2] 24 c5 [2] 0f e9 [2] 21 cb [2] 35 d0 [2] 3a ca [2] 24 d7 [2] 26 d6 [2] 3d d0 [2] 21 d7 [2] 3d f8 }

  condition:
    any of them
}