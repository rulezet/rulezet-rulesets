rule TTP_XOR_QUAD_CurrentVersionRun_34b7 {
  strings:
    $key_34b7 = { 67 d8 [2] 43 d6 [2] 68 fa [2] 46 d8 [2] 52 c3 [2] 5d d9 [2] 43 c4 [2] 41 c5 [2] 5a c3 [2] 46 c4 [2] 5a eb }

  condition:
    any of them
}