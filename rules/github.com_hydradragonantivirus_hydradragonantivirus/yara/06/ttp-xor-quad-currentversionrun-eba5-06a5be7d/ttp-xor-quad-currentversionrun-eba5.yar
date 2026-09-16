rule TTP_XOR_QUAD_CurrentVersionRun_eba5 {
  strings:
    $key_eba5 = { b8 ca [2] 9c c4 [2] b7 e8 [2] 99 ca [2] 8d d1 [2] 82 cb [2] 9c d6 [2] 9e d7 [2] 85 d1 [2] 99 d6 [2] 85 f9 }

  condition:
    any of them
}