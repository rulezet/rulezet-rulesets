rule TTP_XOR_QUAD_CurrentVersionRun_e3a4 {
  strings:
    $key_e3a4 = { b0 cb [2] 94 c5 [2] bf e9 [2] 91 cb [2] 85 d0 [2] 8a ca [2] 94 d7 [2] 96 d6 [2] 8d d0 [2] 91 d7 [2] 8d f8 }

  condition:
    any of them
}