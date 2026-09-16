rule TTP_XOR_QUAD_CurrentVersionRun_73a4 {
  strings:
    $key_73a4 = { 20 cb [2] 04 c5 [2] 2f e9 [2] 01 cb [2] 15 d0 [2] 1a ca [2] 04 d7 [2] 06 d6 [2] 1d d0 [2] 01 d7 [2] 1d f8 }

  condition:
    any of them
}