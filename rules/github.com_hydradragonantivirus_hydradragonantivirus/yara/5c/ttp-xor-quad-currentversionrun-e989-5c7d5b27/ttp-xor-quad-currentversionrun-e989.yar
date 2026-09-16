rule TTP_XOR_QUAD_CurrentVersionRun_e989 {
  strings:
    $key_e989 = { ba e6 [2] 9e e8 [2] b5 c4 [2] 9b e6 [2] 8f fd [2] 80 e7 [2] 9e fa [2] 9c fb [2] 87 fd [2] 9b fa [2] 87 d5 }

  condition:
    any of them
}