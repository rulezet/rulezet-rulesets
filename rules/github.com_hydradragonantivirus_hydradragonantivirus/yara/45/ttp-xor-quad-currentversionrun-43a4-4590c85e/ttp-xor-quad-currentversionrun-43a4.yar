rule TTP_XOR_QUAD_CurrentVersionRun_43a4 {
  strings:
    $key_43a4 = { 10 cb [2] 34 c5 [2] 1f e9 [2] 31 cb [2] 25 d0 [2] 2a ca [2] 34 d7 [2] 36 d6 [2] 2d d0 [2] 31 d7 [2] 2d f8 }

  condition:
    any of them
}