rule TTP_XOR_QUAD_CurrentVersionRun_14b7 {
  strings:
    $key_14b7 = { 47 d8 [2] 63 d6 [2] 48 fa [2] 66 d8 [2] 72 c3 [2] 7d d9 [2] 63 c4 [2] 61 c5 [2] 7a c3 [2] 66 c4 [2] 7a eb }

  condition:
    any of them
}