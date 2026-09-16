rule TTP_XOR_QUAD_CurrentVersionRun_53a5 {
  strings:
    $key_53a5 = { 00 ca [2] 24 c4 [2] 0f e8 [2] 21 ca [2] 35 d1 [2] 3a cb [2] 24 d6 [2] 26 d7 [2] 3d d1 [2] 21 d6 [2] 3d f9 }

  condition:
    any of them
}