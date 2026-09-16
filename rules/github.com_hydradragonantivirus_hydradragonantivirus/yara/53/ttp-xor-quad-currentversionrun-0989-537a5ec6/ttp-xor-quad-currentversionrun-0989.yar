rule TTP_XOR_QUAD_CurrentVersionRun_0989 {
  strings:
    $key_0989 = { 5a e6 [2] 7e e8 [2] 55 c4 [2] 7b e6 [2] 6f fd [2] 60 e7 [2] 7e fa [2] 7c fb [2] 67 fd [2] 7b fa [2] 67 d5 }

  condition:
    any of them
}