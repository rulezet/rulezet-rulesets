rule TTP_XOR_QUAD_CurrentVersionRun_43a5 {
  strings:
    $key_43a5 = { 10 ca [2] 34 c4 [2] 1f e8 [2] 31 ca [2] 25 d1 [2] 2a cb [2] 34 d6 [2] 36 d7 [2] 2d d1 [2] 31 d6 [2] 2d f9 }

  condition:
    any of them
}