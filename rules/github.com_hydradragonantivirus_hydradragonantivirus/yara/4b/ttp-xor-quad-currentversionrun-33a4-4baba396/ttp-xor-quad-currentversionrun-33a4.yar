rule TTP_XOR_QUAD_CurrentVersionRun_33a4 {
  strings:
    $key_33a4 = { 60 cb [2] 44 c5 [2] 6f e9 [2] 41 cb [2] 55 d0 [2] 5a ca [2] 44 d7 [2] 46 d6 [2] 5d d0 [2] 41 d7 [2] 5d f8 }

  condition:
    any of them
}