rule TTP_XOR_QUAD_CurrentVersionRun_0ab7 {
  strings:
    $key_0ab7 = { 59 d8 [2] 7d d6 [2] 56 fa [2] 78 d8 [2] 6c c3 [2] 63 d9 [2] 7d c4 [2] 7f c5 [2] 64 c3 [2] 78 c4 [2] 64 eb }

  condition:
    any of them
}