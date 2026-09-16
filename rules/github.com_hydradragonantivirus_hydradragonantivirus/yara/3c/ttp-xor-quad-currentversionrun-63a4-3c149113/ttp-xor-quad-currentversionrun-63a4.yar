rule TTP_XOR_QUAD_CurrentVersionRun_63a4 {
  strings:
    $key_63a4 = { 30 cb [2] 14 c5 [2] 3f e9 [2] 11 cb [2] 05 d0 [2] 0a ca [2] 14 d7 [2] 16 d6 [2] 0d d0 [2] 11 d7 [2] 0d f8 }

  condition:
    any of them
}