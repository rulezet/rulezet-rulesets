rule TTP_XOR_QUAD_CurrentVersionRun_e1b7 {
  strings:
    $key_e1b7 = { b2 d8 [2] 96 d6 [2] bd fa [2] 93 d8 [2] 87 c3 [2] 88 d9 [2] 96 c4 [2] 94 c5 [2] 8f c3 [2] 93 c4 [2] 8f eb }

  condition:
    any of them
}